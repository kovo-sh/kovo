/**
 * Kovo Hunter v5.1 — agentic trace capture (standalone, unwired).
 *
 * The trace is the fast-iteration substrate for agentic runs: every LLM turn, tool result,
 * planner decision, and lane lifecycle transition is appended to `events.jsonl` under
 * `.kovo/traces/<traceId>/`. Large repeated text (system prompt, tool schemas, prompt
 * prefixes) and bounded sanitized previews live in content-addressed `blobs/<sha256>`.
 *
 * Design constraints:
 * - No imports from the engine (`agent-session`, `execution`, `store`, probes, benchmarks) so
 *   both call sites can import this module without a cycle.
 * - Opt-in only (`KOVO_TRACE=1` or `KOVO_TRACE_DIR`), off by default.
 * - Best-effort: a trace failure must never break an agentic run. Failures are logged once per
 *   writer and the writer degrades to a no-op.
 * - Redaction happens before anything touches disk. The secret map is memory-only and is never
 *   serialized, so a resumed run can re-register the same values and get the same placeholders.
 */
import { execFileSync } from 'node:child_process'
import { createHash, randomBytes } from 'node:crypto'
import {
  appendFileSync,
  chmodSync,
  existsSync,
  mkdirSync,
  readFileSync,
  readdirSync,
  statSync,
  writeFileSync,
  type Dirent,
} from 'node:fs'
import { join } from 'node:path'
import { gunzipSync, gzipSync } from 'node:zlib'

export const traceSchemaVersion = 1
/** Bounded sanitized preview per string/payload (bytes, UTF-8). */
export const maxTracePreviewBytes = 4 * 1024
/** Hard bound for one `events.jsonl` line. Oversize events drop inline previews first. */
export const maxTraceEventBytes = 128 * 1024
const maxArrayItems = 64
const maxObjectKeys = 64
const maxToolCalls = 16
const maxSanitizeDepth = 6

// ---------------------------------------------------------------------------------------------
// Redaction
// ---------------------------------------------------------------------------------------------

export interface SecretRegistration {
  kind: string
  label: string
  /** Deterministic placeholder written to the trace. */
  placeholder: string
}

function normalizeToken(value: string): string {
  const cleaned = (value ?? '').trim().replace(/[^A-Za-z0-9_.-]+/g, '_').replace(/^_+|_+$/g, '')
  return cleaned || 'unknown'
}

function placeholderFor(kind: string, label: string): string {
  const k = normalizeToken(kind)
  const l = normalizeToken(label)
  return k === 'canary' ? `<<CANARY:${l}>>` : `<<SECRET:${k}:${l}>>`
}

const genericRedactions: Array<[RegExp, string]> = [
  // JWTs, including partially registered ones that named replacement did not cover.
  [/\beyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}(?:\.[A-Za-z0-9_-]*)?/g, '<<SECRET:generic:jwt>>'],
  // Provider/API keys.
  [/\b(?:sk-or-v1|sk-ant|sk-proj|sk)-[A-Za-z0-9_-]{12,}\b/g, '<<SECRET:generic:api_key>>'],
  [/\b(?:github_pat|gh[pousr])_[A-Za-z0-9_]{8,}\b/g, '<<SECRET:generic:api_key>>'],
  // Authorization headers / bearer tokens.
  [/\bBearer\s+[A-Za-z0-9._~+/=-]{8,}/gi, 'Bearer <<SECRET:generic:bearer>>'],
  [/\bBasic\s+[A-Za-z0-9+/=]{8,}/gi, 'Basic <<SECRET:generic:basic>>'],
  // Cookie headers and cookie-ish key/value pairs. Never re-redact an existing placeholder.
  [
    /\b(cookie|set-cookie)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|(?!<<)[^\s,;&}\]]+)/gi,
    '$1=<<SECRET:generic:cookie>>',
  ],
  // Generic credential assignments (api_key=..., token: ..., password=...).
  [
    /\b(api[_-]?key|access[_-]?token|auth[_-]?token|token|secret|password|passwd)["']?\s*[:=]\s*(?:"[^"]*"|'[^']*'|(?!<<)[^\s,;&}\]]+)/gi,
    '$1=<<SECRET:generic:api_key>>',
  ],
]

/**
 * Raw secret values keyed by the public (serialization-safe) registration object. Keeping them
 * out of the registration shape means logging/stringifying a registry can never leak a value.
 */
const rawSecretValues = new WeakMap<SecretRegistration, string>()

/**
 * In-memory secret map. Values registered here are replaced by deterministic placeholders
 * before any trace write. The map is never serialized; on resume the caller re-registers the
 * same values and the placeholders line up.
 */
export class SecretRegistry {
  readonly #entries = new Map<string, SecretRegistration>()

  get size(): number {
    return this.#entries.size
  }

  register(kind: string, label: string, value: string): string | null {
    if (typeof value !== 'string' || value.length < 4) return null
    const registration: SecretRegistration = {
      kind: normalizeToken(kind),
      label: normalizeToken(label),
      placeholder: placeholderFor(kind, label),
    }
    this.#entries.set(`${registration.kind}:${registration.label}`, registration)
    // Stash the raw value on a non-enumerable symbol-keyed map entry to keep the public shape
    // serialization-safe even if someone stringifies a registration.
    rawSecretValues.set(registration, value)
    return registration.placeholder
  }

  clear(): void {
    for (const registration of this.#entries.values()) rawSecretValues.delete(registration)
    this.#entries.clear()
  }

  redact(text: string): string {
    if (typeof text !== 'string' || text.length === 0) return text
    let out = text
    const registrations = [...this.#entries.values()]
      .map((registration) => ({ registration, value: rawSecretValues.get(registration) ?? '' }))
      .filter((entry) => entry.value.length >= 4)
      // Longest first so a secret that contains another secret wins.
      .sort((a, b) => b.value.length - a.value.length)
    for (const { registration, value } of registrations) {
      const placeholder = registration.placeholder
      out = out.replaceAll(value, placeholder)
      const encoded = encodeURIComponent(value)
      if (encoded !== value && encoded.length >= 6) out = out.replaceAll(encoded, placeholder)
      const b64 = Buffer.from(value, 'utf8').toString('base64')
      if (b64 !== value && b64.length >= 8) out = out.replaceAll(b64, placeholder)
      const b64url = Buffer.from(value, 'utf8').toString('base64url')
      if (b64url !== value && b64url !== b64 && b64url.length >= 8) out = out.replaceAll(b64url, placeholder)
    }
    // Placeholders are opaque: shield them before each generic pass so key/value patterns
    // (including placeholders introduced by an earlier pass) can never rewrite them.
    const placeholders: string[] = []
    const shield = (value: string): string => value.replace(
      /<<(?:SECRET|CANARY):[A-Za-z0-9_.:-]+>>/g,
      (match) => {
        placeholders.push(match)
        return `<<PH:${placeholders.length - 1}>>`
      },
    )
    for (const [pattern, replacement] of genericRedactions) {
      out = shield(out).replace(pattern, replacement)
    }
    out = out.replace(/<<PH:(\d+)>>/g, (_match, index: string) => placeholders[Number(index)] ?? '')
    return out
  }
  redactValue<T>(value: T): T {
    return sanitizeValue(value, this) as T
  }
}

/** Process-wide registry used by adapters that do not pass their own. */
export const defaultSecretRegistry = new SecretRegistry()

/** Convenience wrapper around {@link defaultSecretRegistry}. */
export function registerSecret(kind: string, label: string, value: string): string | null {
  return defaultSecretRegistry.register(kind, label, value)
}

export function clearRegisteredSecrets(): void {
  defaultSecretRegistry.clear()
}

/** Redact `text` with the process-wide registry. */
export function redactTraceText(text: string): string {
  return defaultSecretRegistry.redact(text)
}

// ---------------------------------------------------------------------------------------------
// Event schema
// ---------------------------------------------------------------------------------------------

export interface ModelParams {
  temperature: number | null
  thinkingLevel: string | null
  maxTokens: number | null
  protocol: string | null
}

export interface Usage {
  input: number
  cachedInput: number
  output: number
  reasoning: number
  costUsd: number
}

/**
 * Bounded payload reference. Exactly one of:
 * - `inline`: sanitized preview (≤ {@link maxTracePreviewBytes}).
 * - `blob`: content-addressed full text (system prompt, tool schema, prompt prefix).
 * - `sha256` + `inline` + `truncated`: large body, hash-only plus a bounded preview.
 */
export interface TracePayload {
  sha256?: string
  blob?: string
  inline?: string
  bytes: number
  truncated: boolean
}

export interface ToolCallRecord {
  callId: string
  name: string
  args?: TracePayload
}

export interface TurnEvent {
  type: 'turn'
  seq: number
  ts: number
  runId: string
  assignmentId: string
  specialistProfile: string
  turnIdx: number
  promptPrefixHash: string | null
  deltaMessages?: TracePayload
  model: string
  modelParams: ModelParams
  ttftMs: number | null
  latencyMs: number | null
  usage: Usage
  stopReason: string | null
  outputTextHash: string | null
  toolCalls: ToolCallRecord[]
}

export interface ToolResultEvent {
  type: 'tool_result'
  seq: number
  ts: number
  assignmentId: string
  turnIdx: number
  callId: string
  name: string
  durationMs: number | null
  ok: boolean
  errorCode: string | null
  summaryJson?: TracePayload
  exchangeIds: string[]
  factIds: string[]
  findingIds: string[]
  verifierFeedback?: TracePayload
  /** HTTP requests issued by this tool call, when known (batching efficiency metric). */
  httpRequests: number | null
}

export interface PlannerDecisionEvent {
  type: 'planner_decision'
  seq: number
  ts: number
  roundIdx: number
  inputStateHash: string
  factsCount: number
  detLeadsCount: number
  alreadyConfirmedCount: number
  spawnedSteps: number
  k6DryStreak: number
  dynamicStepBudget: number
  durationMs: number
  costUsd: number
}

export const lifecycleKinds = ['lane_start', 'lane_end', 'checkpoint', 'verdict', 'abort'] as const
export type LifecycleKind = (typeof lifecycleKinds)[number]

export interface LifecycleEvent {
  type: 'lifecycle'
  seq: number
  ts: number
  kind: LifecycleKind
  payload: Record<string, unknown>
}

export type TraceEvent = TurnEvent | ToolResultEvent | PlannerDecisionEvent | LifecycleEvent

// ---------------------------------------------------------------------------------------------
// Manifest
// ---------------------------------------------------------------------------------------------

export interface TraceManifest {
  traceSchemaVersion: number
  gitSha: string
  app: string
  seed: string | number | null
  mode: string
  model: string
  modelParams: ModelParams
  systemPromptHash: string | null
  toolSchemaHash: string | null
  startedAtMs: number
  endedAtMs: number | null
}

export interface TraceManifestInput {
  gitSha?: string
  app?: string
  seed?: string | number | null
  mode?: string
  model?: string
  modelParams?: Partial<ModelParams>
  systemPromptHash?: string
  toolSchemaHash?: string
  /** When supplied, stored as a blob and hashed into the manifest. */
  systemPrompt?: string
  toolSchema?: string
  startedAtMs?: number
  endedAtMs?: number | null
}

// ---------------------------------------------------------------------------------------------
// Writer API
// ---------------------------------------------------------------------------------------------

export interface AgentTraceOptions {
  dir: string
  manifest: TraceManifestInput
  /** Defaults to the process-wide registry. */
  secrets?: SecretRegistry
  /** Injectable clock for tests; defaults to `Date.now`. */
  now?: () => number
}

export interface TurnRecordInput {
  runId: string
  assignmentId: string
  specialistProfile: string
  turnIdx: number
  promptPrefix?: string
  promptPrefixHash?: string
  deltaMessages?: unknown
  model?: string
  modelParams?: Partial<ModelParams>
  ttftMs?: number | null
  latencyMs?: number | null
  usage?: Partial<Usage>
  stopReason?: string | null
  outputText?: string
  outputTextHash?: string | null
  toolCalls?: Array<{ callId: string; name: string; args?: unknown }>
}

export interface ToolResultRecordInput {
  assignmentId: string
  turnIdx: number
  callId: string
  name: string
  durationMs?: number | null
  ok?: boolean
  errorCode?: string | null
  summaryJson?: unknown
  exchangeIds?: readonly string[]
  factIds?: readonly string[]
  findingIds?: readonly string[]
  verifierFeedback?: unknown
  httpRequests?: number | null
}

export interface PlannerDecisionRecordInput {
  roundIdx: number
  inputStateHash: string
  factsCount?: number
  detLeadsCount?: number
  alreadyConfirmedCount?: number
  spawnedSteps?: number
  k6DryStreak?: number
  dynamicStepBudget?: number
  durationMs?: number
  costUsd?: number
}

export interface TraceSizeSummary {
  dir: string
  enabled: boolean
  events: number
  blobs: number
  bytes: number
  eventsBytes: number
  blobsBytes: number
  manifestBytes: number
}

export interface AgentTrace {
  readonly dir: string
  readonly enabled: boolean
  recordTurn(input: TurnRecordInput): void
  recordToolResult(input: ToolResultRecordInput): void
  recordPlannerDecision(input: PlannerDecisionRecordInput): void
  recordLifecycle(kind: LifecycleKind, payload?: Record<string, unknown>): void
  traceSize(): TraceSizeSummary
  closeTrace(): TraceSizeSummary
}

export function sha256Hex(text: string): string {
  return createHash('sha256').update(text, 'utf8').digest('hex')
}

function byteLength(text: string): number {
  return Buffer.byteLength(text, 'utf8')
}

/** Truncate to `maxBytes` UTF-8 bytes on a codepoint boundary. */
export function truncateUtf8(text: string, maxBytes = maxTracePreviewBytes): { text: string; truncated: boolean; bytes: number } {
  const totalBytes = byteLength(text)
  if (totalBytes <= maxBytes) return { text, truncated: false, bytes: totalBytes }
  const marker = '…[truncated]'
  const markerBytes = byteLength(marker)
  const budget = Math.max(0, maxBytes - markerBytes)
  const buf = Buffer.from(text, 'utf8')
  let end = Math.min(budget, buf.length)
  while (end > 0 && end < buf.length && (buf[end]! & 0xc0) === 0x80) end -= 1
  const preview = buf.subarray(0, end).toString('utf8') + marker
  return { text: preview, truncated: true, bytes: totalBytes }
}

function finiteNumber(value: unknown, fallback = 0): number {
  return typeof value === 'number' && Number.isFinite(value) ? value : fallback
}

function optionalNumber(value: unknown): number | null {
  return typeof value === 'number' && Number.isFinite(value) ? value : null
}

function textValue(value: unknown, fallback = ''): string {
  return typeof value === 'string' ? value : value === null || value === undefined ? fallback : String(value)
}

function normalizeModelParams(input?: Partial<ModelParams> | null): ModelParams {
  return {
    temperature: optionalNumber(input?.temperature),
    thinkingLevel: input?.thinkingLevel === undefined ? null : textValue(input.thinkingLevel) || null,
    maxTokens: optionalNumber(input?.maxTokens),
    protocol: input?.protocol === undefined ? null : textValue(input.protocol) || null,
  }
}

function normalizeUsage(input?: Partial<Usage> | null): Usage {
  return {
    input: finiteNumber(input?.input),
    cachedInput: finiteNumber(input?.cachedInput),
    output: finiteNumber(input?.output),
    reasoning: finiteNumber(input?.reasoning),
    costUsd: finiteNumber(input?.costUsd),
  }
}

function idList(values: readonly string[] | undefined): string[] {
  if (!Array.isArray(values)) return []
  return values.slice(0, maxArrayItems).map((value) => textValue(value)).filter((value) => value.length > 0)
}

/** Recursively redact + bound arbitrary adapter input before it enters an event. */
function sanitizeValue(value: unknown, secrets: SecretRegistry, depth = 0): unknown {
  if (value === null || value === undefined) return value
  if (typeof value === 'string') {
    const redacted = secrets.redact(value)
    return truncateUtf8(redacted).text
  }
  if (typeof value === 'number') return Number.isFinite(value) ? value : null
  if (typeof value === 'boolean') return value
  if (typeof value === 'bigint') return value.toString()
  if (typeof value === 'function' || typeof value === 'symbol') return undefined
  if (depth >= maxSanitizeDepth) return '[depth-limit]'
  if (Array.isArray(value)) {
    return value.slice(0, maxArrayItems).map((item) => sanitizeValue(item, secrets, depth + 1))
  }
  if (value instanceof Error) {
    return { name: value.name, message: truncateUtf8(secrets.redact(value.message)).text }
  }
  if (typeof value === 'object') {
    const out: Record<string, unknown> = {}
    for (const [key, entry] of Object.entries(value as Record<string, unknown>).slice(0, maxObjectKeys)) {
      const sanitized = sanitizeValue(entry, secrets, depth + 1)
      if (sanitized !== undefined) out[key] = sanitized
    }
    return out
  }
  return undefined
}

/** Drop nested inline previews when an event would exceed {@link maxTraceEventBytes}. */
function dropInlinePayloads(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(dropInlinePayloads)
  if (!value || typeof value !== 'object') return value
  const record = value as Record<string, unknown>
  const out: Record<string, unknown> = {}
  for (const [key, entry] of Object.entries(record)) {
    if (key === 'inline' && typeof entry === 'string') continue
    out[key] = dropInlinePayloads(entry)
  }
  return out
}

function ensureBlob(dir: string, text: string): string {
  const sha = sha256Hex(text)
  const blobDir = join(dir, 'blobs')
  const blobPath = join(blobDir, sha)
  if (!existsSync(blobPath)) {
    mkdirSync(blobDir, { recursive: true, mode: 0o700 })
    try {
      chmodSync(blobDir, 0o700)
    } catch {
      // best effort
    }
    const compressed = gzipSync(Buffer.from(text, 'utf8'), { level: 6 })
    try {
      writeFileSync(blobPath, compressed, { mode: 0o600, flag: 'wx' })
    } catch (error) {
      if ((error as NodeJS.ErrnoException).code !== 'EEXIST') throw error
    }
  }
  return sha
}

/** Read a blob back (transparently gunzips when compressed). Returns null when absent. */
export function readBlob(dir: string, sha: string): string | null {
  try {
    const buf = readFileSync(join(dir, 'blobs', sha))
    const plain = buf.length >= 2 && buf[0] === 0x1f && buf[1] === 0x8b ? gunzipSync(buf) : buf
    return plain.toString('utf8')
  } catch {
    return null
  }
}

function resolveGitSha(): string {
  const fromEnv = process.env.KOVO_GIT_SHA?.trim()
  if (fromEnv) return fromEnv
  try {
    return execFileSync('git', ['rev-parse', 'HEAD'], {
      encoding: 'utf8',
      timeout: 1_000,
      stdio: ['ignore', 'pipe', 'ignore'],
    }).trim()
  } catch {
    return 'unknown'
  }
}

function dirUsage(dir: string): { files: number; bytes: number } {
  let files = 0
  let bytes = 0
  let entries: Dirent[] = []
  try {
    entries = readdirSync(dir, { withFileTypes: true })
  } catch {
    return { files, bytes }
  }
  for (const entry of entries) {
    const path = join(dir, entry.name)
    if (entry.isDirectory()) {
      const nested = dirUsage(path)
      files += nested.files
      bytes += nested.bytes
    } else if (entry.isFile()) {
      try {
        files += 1
        bytes += statSync(path).size
      } catch {
        // best effort
      }
    }
  }
  return { files, bytes }
}

class TraceWriter implements AgentTrace {
  readonly dir: string
  readonly enabled = true
  readonly #eventsPath: string
  readonly #secrets: SecretRegistry
  readonly #now: () => number
  #manifest: TraceManifest
  #seq = 1
  #written = 0
  #warned = false
  #closed = false

  constructor(dir: string, manifest: TraceManifest, secrets: SecretRegistry, now: () => number) {
    this.dir = dir
    this.#manifest = manifest
    this.#secrets = secrets
    this.#now = now
    this.#eventsPath = join(dir, 'events.jsonl')
  }

  static open(options: AgentTraceOptions): TraceWriter {
    const now = options.now ?? Date.now
    const secrets = options.secrets ?? defaultSecretRegistry
    const dir = options.dir
    mkdirSync(dir, { recursive: true, mode: 0o700 })
    try {
      chmodSync(dir, 0o700)
    } catch {
      // best effort
    }
    mkdirSync(join(dir, 'blobs'), { recursive: true, mode: 0o700 })

    const input = options.manifest
    const systemPromptHash = input.systemPromptHash
      ?? (typeof input.systemPrompt === 'string' ? ensureBlob(dir, secrets.redact(input.systemPrompt)) : null)
    const toolSchemaHash = input.toolSchemaHash
      ?? (typeof input.toolSchema === 'string' ? ensureBlob(dir, secrets.redact(input.toolSchema)) : null)

    const manifest: TraceManifest = {
      traceSchemaVersion,
      gitSha: input.gitSha ?? resolveGitSha(),
      app: textValue(input.app, 'unknown') || 'unknown',
      seed: input.seed ?? null,
      mode: textValue(input.mode, 'unknown') || 'unknown',
      model: textValue(input.model, 'unknown') || 'unknown',
      modelParams: normalizeModelParams(input.modelParams),
      systemPromptHash,
      toolSchemaHash,
      startedAtMs: finiteNumber(input.startedAtMs ?? now()),
      endedAtMs: input.endedAtMs ?? null,
    }
    const writer = new TraceWriter(dir, manifest, secrets, now)
    writer.writeManifest()
    appendFileSync(writer.#eventsPath, '', { mode: 0o600 })
    return writer
  }

  recordTurn(input: TurnRecordInput): void {
    if (!this.enabled || this.#closed) return
    try {
      const promptPrefixHash = input.promptPrefixHash
        ?? (typeof input.promptPrefix === 'string'
          ? ensureBlob(this.dir, this.#secrets.redact(input.promptPrefix))
          : null)
      const event: TurnEvent = {
        type: 'turn',
        seq: this.#seq++,
        ts: this.#now(),
        runId: textValue(input.runId),
        assignmentId: textValue(input.assignmentId),
        specialistProfile: textValue(input.specialistProfile),
        turnIdx: finiteNumber(input.turnIdx),
        promptPrefixHash,
        deltaMessages: this.payloadFor(input.deltaMessages, { previewOnly: true }),
        model: textValue(input.model, this.#manifest.model) || this.#manifest.model,
        modelParams: normalizeModelParams(input.modelParams ?? this.#manifest.modelParams),
        ttftMs: optionalNumber(input.ttftMs),
        latencyMs: optionalNumber(input.latencyMs),
        usage: normalizeUsage(input.usage),
        stopReason: input.stopReason === undefined ? null : input.stopReason,
        outputTextHash: input.outputTextHash
          ?? (typeof input.outputText === 'string' ? sha256Hex(this.#secrets.redact(input.outputText)) : null),
        toolCalls: (input.toolCalls ?? []).slice(0, maxToolCalls).map((call) => ({
          callId: textValue(call.callId),
          name: textValue(call.name),
          args: this.payloadFor(call.args, { previewOnly: true }),
        })),
      }
      this.writeEvent(event)
    } catch (error) {
      this.fail(error)
    }
  }

  recordToolResult(input: ToolResultRecordInput): void {
    if (!this.enabled || this.#closed) return
    try {
      const event: ToolResultEvent = {
        type: 'tool_result',
        seq: this.#seq++,
        ts: this.#now(),
        assignmentId: textValue(input.assignmentId),
        turnIdx: finiteNumber(input.turnIdx),
        callId: textValue(input.callId),
        name: textValue(input.name),
        durationMs: optionalNumber(input.durationMs),
        ok: input.ok !== false,
        errorCode: input.errorCode === undefined ? null : input.errorCode,
        summaryJson: this.payloadFor(input.summaryJson, { previewOnly: true }),
        exchangeIds: idList(input.exchangeIds),
        factIds: idList(input.factIds),
        findingIds: idList(input.findingIds),
        verifierFeedback: this.payloadFor(input.verifierFeedback, { previewOnly: true }),
        httpRequests: optionalNumber(input.httpRequests),
      }
      this.writeEvent(event)
    } catch (error) {
      this.fail(error)
    }
  }

  recordPlannerDecision(input: PlannerDecisionRecordInput): void {
    if (!this.enabled || this.#closed) return
    try {
      const event: PlannerDecisionEvent = {
        type: 'planner_decision',
        seq: this.#seq++,
        ts: this.#now(),
        roundIdx: finiteNumber(input.roundIdx),
        inputStateHash: textValue(input.inputStateHash),
        factsCount: finiteNumber(input.factsCount),
        detLeadsCount: finiteNumber(input.detLeadsCount),
        alreadyConfirmedCount: finiteNumber(input.alreadyConfirmedCount),
        spawnedSteps: finiteNumber(input.spawnedSteps),
        k6DryStreak: finiteNumber(input.k6DryStreak),
        dynamicStepBudget: finiteNumber(input.dynamicStepBudget),
        durationMs: finiteNumber(input.durationMs),
        costUsd: finiteNumber(input.costUsd),
      }
      this.writeEvent(event)
    } catch (error) {
      this.fail(error)
    }
  }

  recordLifecycle(kind: LifecycleKind, payload: Record<string, unknown> = {}): void {
    if (!this.enabled || this.#closed) return
    try {
      const safeKind = lifecycleKinds.includes(kind) ? kind : 'checkpoint'
      const event: LifecycleEvent = {
        type: 'lifecycle',
        seq: this.#seq++,
        ts: this.#now(),
        kind: safeKind,
        payload: (sanitizeValue(payload, this.#secrets) as Record<string, unknown>) ?? {},
      }
      this.writeEvent(event)
    } catch (error) {
      this.fail(error)
    }
  }

  traceSize(): TraceSizeSummary {
    const all = dirUsage(this.dir)
    const blobs = dirUsage(join(this.dir, 'blobs'))
    let eventsBytes = 0
    let manifestBytes = 0
    try {
      eventsBytes = statSync(this.#eventsPath).size
    } catch {
      // best effort
    }
    try {
      manifestBytes = statSync(join(this.dir, 'manifest.json')).size
    } catch {
      // best effort
    }
    return {
      dir: this.dir,
      enabled: true,
      events: this.#written,
      blobs: blobs.files,
      bytes: all.bytes,
      eventsBytes,
      blobsBytes: blobs.bytes,
      manifestBytes,
    }
  }

  closeTrace(): TraceSizeSummary {
    if (!this.#closed) {
      this.#closed = true
      try {
        this.#manifest = { ...this.#manifest, endedAtMs: this.#now() }
        this.writeManifest()
      } catch (error) {
        this.fail(error)
      }
    }
    return this.traceSize()
  }

  private payloadFor(value: unknown, options: { previewOnly: boolean }): TracePayload | undefined {
    if (value === undefined || value === null) return undefined
    const sanitized = typeof value === 'string' ? this.#secrets.redact(value) : sanitizeValue(value, this.#secrets)
    if (sanitized === undefined || sanitized === null) return undefined
    const text = typeof sanitized === 'string' ? sanitized : JSON.stringify(sanitized)
    const bytes = byteLength(text)
    const sha256 = sha256Hex(text)
    if (bytes <= maxTracePreviewBytes) return { inline: text, bytes, truncated: false }
    if (!options.previewOnly) {
      try {
        return { blob: ensureBlob(this.dir, text), bytes, truncated: false }
      } catch {
        // fall through to hash + preview
      }
    }
    return {
      sha256,
      inline: truncateUtf8(text).text,
      bytes,
      truncated: true,
    }
  }

  private writeEvent(event: TraceEvent): void {
    let line = JSON.stringify(event)
    if (byteLength(line) > maxTraceEventBytes) {
      const reduced = dropInlinePayloads(event) as Record<string, unknown>
      reduced.truncated = true
      line = JSON.stringify(reduced)
    }
    if (byteLength(line) > maxTraceEventBytes) {
      line = JSON.stringify({
        type: event.type,
        seq: event.seq,
        ts: event.ts,
        truncated: true,
        oversizeBytes: byteLength(line),
      })
    }
    appendFileSync(this.#eventsPath, `${line}\n`, { mode: 0o600 })
    this.#written += 1
  }

  private writeManifest(): void {
    writeFileSync(join(this.dir, 'manifest.json'), `${JSON.stringify(this.#manifest, null, 2)}\n`, {
      mode: 0o600,
    })
  }

  private fail(error: unknown): void {
    if (this.#warned) return
    this.#warned = true
    const message = error instanceof Error ? error.message : String(error)
    try {
      console.warn(`[kovo-trace] disabled after write failure at ${this.dir}: ${message}`)
    } catch {
      // never throw from logging
    }
  }
}

class DisabledTrace implements AgentTrace {
  readonly dir: string
  readonly enabled = false

  constructor(dir: string) {
    this.dir = dir
  }

  recordTurn(): void {}
  recordToolResult(): void {}
  recordPlannerDecision(): void {}
  recordLifecycle(): void {}
  traceSize(): TraceSizeSummary {
    return {
      dir: this.dir,
      enabled: false,
      events: 0,
      blobs: 0,
      bytes: 0,
      eventsBytes: 0,
      blobsBytes: 0,
      manifestBytes: 0,
    }
  }
  closeTrace(): TraceSizeSummary {
    return this.traceSize()
  }
}

/**
 * Open a trace writer. Never throws: when the directory cannot be created the writer degrades
 * to a no-op so tracing can never take down an agentic run.
 */
export function createAgentTrace(options: AgentTraceOptions): AgentTrace {
  try {
    return TraceWriter.open(options)
  } catch (error) {
    const message = error instanceof Error ? error.message : String(error)
    try {
      console.warn(`[kovo-trace] disabled, could not open ${options.dir}: ${message}`)
    } catch {
      // never throw from logging
    }
    return new DisabledTrace(options.dir)
  }
}

// ---------------------------------------------------------------------------------------------
// Env opt-in + reader
// ---------------------------------------------------------------------------------------------

export interface TraceEnvConfig {
  enabled: boolean
  dir: string | null
}

/** Resolve trace opt-in from the environment. Off unless explicitly enabled. */
export function resolveTraceConfig(env: NodeJS.ProcessEnv = process.env): TraceEnvConfig {
  const explicitDir = env.KOVO_TRACE_DIR?.trim()
  if (explicitDir) return { enabled: true, dir: explicitDir }
  const flag = env.KOVO_TRACE?.trim().toLowerCase()
  if (flag === '1' || flag === 'true' || flag === 'yes') {
    const root = env.KOVO_TRACE_ROOT?.trim() || join('.kovo', 'traces')
    const id = env.KOVO_TRACE_ID?.trim()
      || `${env.KOVO_TRACE_NAME?.trim() || 'run'}-${Date.now().toString(36)}-${randomBytes(3).toString('hex')}`
    return { enabled: true, dir: join(root, id) }
  }
  return { enabled: false, dir: null }
}

/** Create a trace from the environment, or null when tracing is off. Never throws. */
export function createAgentTraceFromEnv(
  manifest: TraceManifestInput,
  env: NodeJS.ProcessEnv = process.env,
  secrets: SecretRegistry = defaultSecretRegistry,
): AgentTrace | null {
  const config = resolveTraceConfig(env)
  if (!config.enabled || !config.dir) return null
  return createAgentTrace({ dir: config.dir, manifest, secrets })
}

export interface ReadTraceResult {
  dir: string
  manifest: TraceManifest | null
  events: TraceEvent[]
  issues: string[]
}

function isTraceEvent(value: unknown): value is TraceEvent {
  if (!value || typeof value !== 'object') return false
  const record = value as Record<string, unknown>
  return (
    typeof record.seq === 'number'
    && typeof record.ts === 'number'
    && (record.type === 'turn'
      || record.type === 'tool_result'
      || record.type === 'planner_decision'
      || record.type === 'lifecycle')
  )
}

/** Read a trace for the metrics CLI. Malformed lines are reported, never thrown. */
export function readTrace(dir: string): ReadTraceResult {
  const issues: string[] = []
  let manifest: TraceManifest | null = null
  try {
    const parsed = JSON.parse(readFileSync(join(dir, 'manifest.json'), 'utf8')) as TraceManifest
    manifest = parsed
    if (parsed.traceSchemaVersion !== traceSchemaVersion) {
      issues.push(`manifest schema ${String(parsed.traceSchemaVersion)} != ${traceSchemaVersion}`)
    }
  } catch (error) {
    issues.push(`manifest unreadable: ${error instanceof Error ? error.message : String(error)}`)
  }
  const events: TraceEvent[] = []
  let raw = ''
  try {
    raw = readFileSync(join(dir, 'events.jsonl'), 'utf8')
  } catch (error) {
    issues.push(`events unreadable: ${error instanceof Error ? error.message : String(error)}`)
  }
  for (const [index, line] of raw.split('\n').entries()) {
    if (!line.trim()) continue
    try {
      const parsed: unknown = JSON.parse(line)
      if (!isTraceEvent(parsed)) {
        issues.push(`line ${index + 1}: not a trace event`)
        continue
      }
      events.push(parsed)
    } catch {
      issues.push(`line ${index + 1}: invalid JSON`)
    }
  }
  events.sort((a, b) => a.seq - b.seq)
  return { dir, manifest, events, issues }
}
