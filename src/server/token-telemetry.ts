/**
 * Per-Run Structured Cost, Token, Cache & Reliability Telemetry Accumulator (Gap #4).
 *
 * Tracks bounded, secret-free per-run economics in memory:
 *  - Input / cached / uncached / output / reasoning token counts and prompt-cache hit rate
 *  - Total USD spend vs. retry / stall / truncated-tool-call waste USD
 *  - Provider stall, retry, truncated-tool-call, and wall-clock rotation counts
 *  - Per-tool result byte & spill volume ranked to surface context-bloat drivers
 *
 * Never stores raw prompts, payloads, headers, tool arguments, tool bodies, or secrets.
 */
import { registerRunDisposer } from './run-disposers.ts'

export const MAX_TRACKED_RUN_TELEMETRY = 512
export const MAX_TOOLS_PER_RUN_TELEMETRY = 128
const MAX_RUN_ID_CHARS = 128
const MAX_TOOL_NAME_CHARS = 64
const MAX_PROVIDER_KEY_CHARS = 96
const MAX_PROVIDERS_PER_RUN_TELEMETRY = 64
const OVERFLOW_TOOL_BUCKET = '__other__'

const SAFE_TOOL_CHAR_RE = /[^A-Za-z0-9_.:/-]/g
const CONTROL_OR_SPACE_RE = /[\s\0-\x1f\x7f]+/g
const CONTROL_CHAR_RE = /[\0-\x1f\x7f]+/g

export type ProviderUsageTelemetryOutcome =
  | 'ok'
  | 'stalled'
  | 'retried'
  | 'truncated'
  | 'aborted'
  | 'error'

export interface ProviderUsageTelemetryInput {
  runId: string
  /** Optional provider profile ID for per-provider telemetry breakdown. */
  profileId?: string
  /** Optional human-readable provider profile name for per-provider telemetry breakdown. */
  providerName?: string
  /** Optional model identifier for per-provider telemetry breakdown. */
  model?: string
  inputTokens?: number
  cachedInputTokens?: number
  uncachedInputTokens?: number
  outputTokens?: number
  reasoningTokens?: number
  costUsd?: number
  /** Outcome classification for this provider call attempt. */
  outcome?: ProviderUsageTelemetryOutcome
  /** Explicit marker that this attempt stalled (first-event, idle, or no-token watchdog timeout). */
  stalled?: boolean
  /** Explicit marker that this attempt was retried or failed over. */
  retried?: boolean
  /** Explicit retry count increment when a single call aggregates retries (default 1 when `retried` is true). */
  retryCount?: number
  /** Truncated/malformed tool calls observed on this attempt (`boolean` or count). */
  truncatedToolCalls?: number | boolean
  /** Optional wall-clock rotation increment associated with this telemetry update. */
  wallClockRotation?: boolean
  /** Set false when attributing a retry/failover marker onto an already-counted stalled attempt. */
  countCall?: boolean
}

export interface ProviderTelemetryBreakdownEntry {
  calls: number
  retries: number
  stalls: number
  inputTokens: number
  cachedInputTokens: number
  outputTokens: number
  costUsd: number
  cacheHitRate: number
}

interface ProviderBreakdownAccumulator {
  calls: number
  retries: number
  stalls: number
  inputTokens: number
  cachedInputTokens: number
  uncachedInputTokens: number
  outputTokens: number
  costUsd: number
}

export interface ToolResultSizeTelemetryInput {
  runId: string
  toolName: string
  bytes: number
  spilled?: boolean
}

export interface ToolResultBytesStats {
  calls: number
  bytes: number
  spilledCount: number
}

export interface ToolResultByteDriver extends ToolResultBytesStats {
  toolName: string
}

export interface RunTokenTelemetrySummary {
  runId: string
  inputTokens: number
  cachedInputTokens: number
  uncachedInputTokens: number
  outputTokens: number
  reasoningTokens: number
  /** Prompt-cache hit rate: `cachedInputTokens / (cachedInputTokens + uncachedInputTokens)`, or `0` when zero input tokens. */
  cacheHitRate: number
  totalCostUsd: number
  /** Cost spent on stalled, retried, truncated-tool-call, or errored/aborted provider attempts. */
  retryStallWasteUsd: number
  providerCalls: number
  providerRetries: number
  providerStalls: number
  truncatedToolCalls: number
  wallClockRotations: number
  totalToolResultBytes: number
  toolResultSpills: number
  toolResultBytesByTool: Record<string, ToolResultBytesStats>
  /** Top tool-result byte drivers ranked descending by total `bytes`, then `calls`, then `toolName`. */
  topToolResultDrivers: ToolResultByteDriver[]
  /** Per-provider token, cost, cache, retry, and stall breakdown keyed by provider name / profile ID / model. */
  providerBreakdown: Record<string, ProviderTelemetryBreakdownEntry>
}

interface RunTokenTelemetryState {
  inputTokens: number
  cachedInputTokens: number
  uncachedInputTokens: number
  outputTokens: number
  reasoningTokens: number
  totalCostUsd: number
  retryStallWasteUsd: number
  providerCalls: number
  providerRetries: number
  providerStalls: number
  truncatedToolCalls: number
  wallClockRotations: number
  totalToolResultBytes: number
  toolResultSpills: number
  toolResultBytesByTool: Map<string, ToolResultBytesStats>
  providerBreakdown: Map<string, ProviderBreakdownAccumulator>
}

const runTelemetryStore = new Map<string, RunTokenTelemetryState>()

function normalizeRunId(runId: string): string {
  if (typeof runId !== 'string') return ''
  const cleaned = runId.trim().replace(CONTROL_OR_SPACE_RE, '_').slice(0, MAX_RUN_ID_CHARS)
  return cleaned
}

function sanitizeToolName(toolName: string): string {
  if (typeof toolName !== 'string') return 'unknown'
  const cleaned = toolName
    .trim()
    .replace(SAFE_TOOL_CHAR_RE, '_')
    .slice(0, MAX_TOOL_NAME_CHARS)
  return cleaned || 'unknown'
}

function nonNegInt(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return 0
  return Math.floor(value)
}

function nonNegFloat(value: unknown): number {
  if (typeof value !== 'number' || !Number.isFinite(value) || value <= 0) return 0
  return value
}

function sanitizeProviderKey(input: Pick<ProviderUsageTelemetryInput, 'providerName' | 'profileId' | 'model'>): string | null {
  const candidate = [input.providerName, input.profileId, input.model].find(
    v => typeof v === 'string' && v.trim().length > 0,
  )
  if (!candidate) return null
  const cleaned = candidate.replace(CONTROL_CHAR_RE, ' ').trim().slice(0, MAX_PROVIDER_KEY_CHARS)
  return cleaned || null
}

function createEmptyState(): RunTokenTelemetryState {
  return {
    inputTokens: 0,
    cachedInputTokens: 0,
    uncachedInputTokens: 0,
    outputTokens: 0,
    reasoningTokens: 0,
    totalCostUsd: 0,
    retryStallWasteUsd: 0,
    providerCalls: 0,
    providerRetries: 0,
    providerStalls: 0,
    truncatedToolCalls: 0,
    wallClockRotations: 0,
    totalToolResultBytes: 0,
    toolResultSpills: 0,
    toolResultBytesByTool: new Map(),
    providerBreakdown: new Map(),
  }
}

function getOrCreateRunState(runId: string): RunTokenTelemetryState {
  const existing = runTelemetryStore.get(runId)
  if (existing) {
    // Refresh insertion order for bounded LRU eviction.
    runTelemetryStore.delete(runId)
    runTelemetryStore.set(runId, existing)
    return existing
  }
  while (runTelemetryStore.size >= MAX_TRACKED_RUN_TELEMETRY) {
    const oldestKey = runTelemetryStore.keys().next().value
    if (oldestKey === undefined) break
    runTelemetryStore.delete(oldestKey)
  }
  const created = createEmptyState()
  runTelemetryStore.set(runId, created)
  return created
}

/**
 * Rank tool-result byte drivers descending by total `bytes`, then `calls`, then `toolName`.
 */
export function rankToolResultByteDrivers(
  byTool: Readonly<Record<string, ToolResultBytesStats>>,
  limit?: number,
): ToolResultByteDriver[] {
  const ranked: ToolResultByteDriver[] = Object.entries(byTool).map(([toolName, stats]) => ({
    toolName,
    calls: stats.calls,
    bytes: stats.bytes,
    spilledCount: stats.spilledCount,
  }))
  ranked.sort((a, b) =>
    b.bytes - a.bytes
    || b.calls - a.calls
    || a.toolName.localeCompare(b.toolName),
  )
  if (limit !== undefined && Number.isFinite(limit) && limit >= 0) {
    return ranked.slice(0, Math.floor(limit))
  }
  return ranked
}

/**
 * Record structured token, prompt-cache, cost, stall, retry, and tool-call truncation telemetry
 * for a single provider attempt under `input.runId`.
 */
export function recordProviderUsageTelemetry(input: ProviderUsageTelemetryInput): void {
  const runId = normalizeRunId(input.runId)
  if (!runId) return

  const state = getOrCreateRunState(runId)

  const rawCached = nonNegInt(input.cachedInputTokens)
  let addInput = 0
  let addCached = 0
  let addUncached = 0

  if (input.uncachedInputTokens !== undefined) {
    addUncached = nonNegInt(input.uncachedInputTokens)
    addCached = rawCached
    const explicitInput = nonNegInt(input.inputTokens)
    addInput = Math.max(explicitInput, addCached + addUncached)
  } else {
    addInput = nonNegInt(input.inputTokens)
    addCached = Math.min(addInput, rawCached)
    addUncached = Math.max(0, addInput - addCached)
  }

  const addOutput = nonNegInt(input.outputTokens)
  const addReasoning = nonNegInt(input.reasoningTokens)
  const addCost = nonNegFloat(input.costUsd)

  const isStalled = Boolean(input.stalled || input.outcome === 'stalled')
  const isRetried = Boolean(input.retried || input.outcome === 'retried')
  const explicitRetryCount = nonNegInt(input.retryCount)
  const addRetries = isRetried ? Math.max(1, explicitRetryCount) : 0

  const addTruncated = typeof input.truncatedToolCalls === 'number'
    ? nonNegInt(input.truncatedToolCalls)
    : (input.truncatedToolCalls ? 1 : (input.outcome === 'truncated' ? 1 : 0))

  const isWastedAttempt =
    isStalled
    || isRetried
    || addTruncated > 0
    || input.outcome === 'aborted'
    || input.outcome === 'error'

  state.inputTokens += addInput
  state.cachedInputTokens += addCached
  state.uncachedInputTokens += addUncached
  state.outputTokens += addOutput
  state.reasoningTokens += addReasoning
  state.totalCostUsd += addCost
  if (isWastedAttempt) {
    state.retryStallWasteUsd += addCost
  }
  if (input.countCall !== false) {
    state.providerCalls += 1
  }
  if (isStalled) {
    state.providerStalls += 1
  }
  state.providerRetries += addRetries
  state.truncatedToolCalls += addTruncated
  if (input.wallClockRotation) {
    state.wallClockRotations += 1
  }

  const rawProviderKey = sanitizeProviderKey(input)
  if (rawProviderKey) {
    const providerKey = state.providerBreakdown.has(rawProviderKey) || state.providerBreakdown.size < MAX_PROVIDERS_PER_RUN_TELEMETRY
      ? rawProviderKey
      : OVERFLOW_TOOL_BUCKET
    let entry = state.providerBreakdown.get(providerKey)
    if (!entry) {
      entry = {
        calls: 0,
        retries: 0,
        stalls: 0,
        inputTokens: 0,
        cachedInputTokens: 0,
        uncachedInputTokens: 0,
        outputTokens: 0,
        costUsd: 0,
      }
      state.providerBreakdown.set(providerKey, entry)
    }
    if (input.countCall !== false) entry.calls += 1
    entry.retries += addRetries
    if (isStalled) entry.stalls += 1
    entry.inputTokens += addInput
    entry.cachedInputTokens += addCached
    entry.uncachedInputTokens += addUncached
    entry.outputTokens += addOutput
    entry.costUsd += addCost
  }
}

/**
 * Record tool-result byte volume (and spill flag) by tool name so oversized context drivers
 * (e.g., `derive_evidence`, `request_http`, `query_facts`) are immediately visible per run.
 */
export function recordToolResultSizeTelemetry(input: ToolResultSizeTelemetryInput): void {
  const runId = normalizeRunId(input.runId)
  if (!runId) return

  const state = getOrCreateRunState(runId)
  const rawName = sanitizeToolName(input.toolName)
  const toolKey = state.toolResultBytesByTool.has(rawName) || state.toolResultBytesByTool.size < MAX_TOOLS_PER_RUN_TELEMETRY
    ? rawName
    : OVERFLOW_TOOL_BUCKET

  const addBytes = nonNegInt(input.bytes)
  const addSpill = input.spilled ? 1 : 0

  const existing = state.toolResultBytesByTool.get(toolKey)
  if (existing) {
    existing.calls += 1
    existing.bytes += addBytes
    existing.spilledCount += addSpill
  } else {
    state.toolResultBytesByTool.set(toolKey, {
      calls: 1,
      bytes: addBytes,
      spilledCount: addSpill,
    })
  }
  state.totalToolResultBytes += addBytes
  state.toolResultSpills += addSpill
}

/**
 * Record wall-clock worker/session rotations under `runId`.
 */
export function recordWallClockRotationTelemetry(runId: string, count = 1): void {
  const normalized = normalizeRunId(runId)
  if (!normalized) return
  const add = nonNegInt(count)
  if (add <= 0) return
  const state = getOrCreateRunState(normalized)
  state.wallClockRotations += add
}

/**
 * Return a fresh, secret-free structured snapshot of token & cost telemetry for `runId`.
 * Does not allocate state for unknown or already-disposed runs.
 */
export function getRunTokenTelemetrySummary(runId: string): RunTokenTelemetrySummary {
  const normalized = normalizeRunId(runId)
  const state = normalized ? runTelemetryStore.get(normalized) : undefined
  if (!state) {
    return {
      runId: normalized,
      inputTokens: 0,
      cachedInputTokens: 0,
      uncachedInputTokens: 0,
      outputTokens: 0,
      reasoningTokens: 0,
      cacheHitRate: 0,
      totalCostUsd: 0,
      retryStallWasteUsd: 0,
      providerCalls: 0,
      providerRetries: 0,
      providerStalls: 0,
      truncatedToolCalls: 0,
      wallClockRotations: 0,
      totalToolResultBytes: 0,
      toolResultSpills: 0,
      toolResultBytesByTool: {},
      topToolResultDrivers: [],
      providerBreakdown: {},
    }
  }

  const rawByTool: Record<string, ToolResultBytesStats> = {}
  for (const [toolName, stats] of state.toolResultBytesByTool.entries()) {
    rawByTool[toolName] = {
      calls: stats.calls,
      bytes: stats.bytes,
      spilledCount: stats.spilledCount,
    }
  }
  const topToolResultDrivers = rankToolResultByteDrivers(rawByTool)
  const toolResultBytesByTool: Record<string, ToolResultBytesStats> = {}
  for (const driver of topToolResultDrivers) {
    toolResultBytesByTool[driver.toolName] = {
      calls: driver.calls,
      bytes: driver.bytes,
      spilledCount: driver.spilledCount,
    }
  }

  const providerBreakdown: Record<string, ProviderTelemetryBreakdownEntry> = {}
  for (const [providerKey, stats] of state.providerBreakdown.entries()) {
    const providerCacheDenom = stats.cachedInputTokens + stats.uncachedInputTokens
    providerBreakdown[providerKey] = {
      calls: stats.calls,
      retries: stats.retries,
      stalls: stats.stalls,
      inputTokens: stats.inputTokens,
      cachedInputTokens: stats.cachedInputTokens,
      outputTokens: stats.outputTokens,
      costUsd: stats.costUsd,
      cacheHitRate: providerCacheDenom > 0 ? stats.cachedInputTokens / providerCacheDenom : 0,
    }
  }

  const cacheDenominator = state.cachedInputTokens + state.uncachedInputTokens
  const cacheHitRate = cacheDenominator > 0 ? state.cachedInputTokens / cacheDenominator : 0

  return {
    runId: normalized,
    inputTokens: state.inputTokens,
    cachedInputTokens: state.cachedInputTokens,
    uncachedInputTokens: state.uncachedInputTokens,
    outputTokens: state.outputTokens,
    reasoningTokens: state.reasoningTokens,
    cacheHitRate,
    totalCostUsd: state.totalCostUsd,
    retryStallWasteUsd: state.retryStallWasteUsd,
    providerCalls: state.providerCalls,
    providerRetries: state.providerRetries,
    providerStalls: state.providerStalls,
    truncatedToolCalls: state.truncatedToolCalls,
    wallClockRotations: state.wallClockRotations,
    totalToolResultBytes: state.totalToolResultBytes,
    toolResultSpills: state.toolResultSpills,
    toolResultBytesByTool,
    topToolResultDrivers,
    providerBreakdown,
  }
}

export function hasRunTokenTelemetry(runId: string): boolean {
  const normalized = normalizeRunId(runId)
  return normalized ? runTelemetryStore.has(normalized) : false
}

export function getTrackedRunTelemetryCount(): number {
  return runTelemetryStore.size
}

/**
 * Dispose all in-memory telemetry for `runId` (idempotent; prevents unbounded per-run retention).
 */
export function disposeRunTokenTelemetry(runId: string): boolean {
  const normalized = normalizeRunId(runId)
  if (!normalized) return false
  return runTelemetryStore.delete(normalized)
}

registerRunDisposer('token-telemetry:run-store', runId => {
  disposeRunTokenTelemetry(runId)
})
