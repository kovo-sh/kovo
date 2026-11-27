/**
 * Kovo v5.1 — trace metrics CLI.
 *
 * Reads `.kovo/traces/<id>/` (manifest + events) and computes the nine fast-loop metrics
 * accepted in plans/ROADMAP-v5.md. Prints a compact table (or `--json`) and never dumps raw
 * prompts or HTTP bodies.
 *
 * Usage:
 *   node scripts/trace-metrics.ts --trace .kovo/traces/<id>
 *   node scripts/trace-metrics.ts --trace <dir> --control <summary.json> --json
 *   node scripts/trace-metrics.ts --trace <dir> --gate
 */
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import {
  readTrace,
  type LifecycleEvent,
  type PlannerDecisionEvent,
  type ToolResultEvent,
  type TraceEvent,
  type TraceManifest,
  type TracePayload,
  type TurnEvent,
} from '../src/server/agent-trace.ts'

export interface TraceControlSummary {
  /** Total confirmed findings in the control run. */
  confirmed?: number
  /** Stable finding IDs confirmed by the control run (best precision for ΔConfirmed). */
  confirmedFindingIds?: string[]
  /** Confirmed counts by vuln class, for class-scoped ΔConfirmed. */
  confirmedByClass?: Record<string, number>
}

export interface TraceMetrics {
  traceDir: string
  events: number
  /** Non-decoy unique confirmed verdicts. */
  confirmed: number
  /** Unique confirmed verdicts that targeted a decoy/control. */
  decoyFalsePositives: number
  /** Precision over verdicts: trueConfirmed / (confirmed + verifier-reported false positives). */
  precision: number
  /** ΔConfirmed vs a supplied control summary; null when no control was supplied. */
  deltaConfirmed: number | null
  /** First probe tool result or probe lane start, relative to manifest start. */
  timeToFirstProbeMs: number | null
  /** Unique assignment IDs per 10 minutes of wall clock. */
  assignmentsPer10Min: number
  /** Probed fact signals / all discovered fact signals (1 when there are no signals). */
  signalToSpecConversion: number
  /** LLM turns with no tool calls / all LLM turns. */
  wastedTurnRatio: number
  /** HTTP requests per LLM turn. */
  batchingEfficiency: number
  /** OLS slope of per-turn input tokens against turnIdx. */
  contextGrowthSlope: number
  /** Total model spend divided by additive confirmed findings; null when none. */
  costPerAdditiveConfirmedUsd: number | null
  /** Supporting totals (not part of the nine). */
  totals: {
    turns: number
    toolResults: number
    assignments: number
    signals: number
    probedSignals: number
    httpRequests: number
    costUsd: number
    spanMs: number
  }
}

export interface TraceGate {
  precisionOk: boolean
  decoyOk: boolean
  throughputOk: boolean
  pass: boolean
}

function payloadObject(payload: TracePayload | undefined): Record<string, unknown> | null {
  if (!payload?.inline) return null
  try {
    const parsed: unknown = JSON.parse(payload.inline)
    return parsed && typeof parsed === 'object' && !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null
  } catch {
    return null
  }
}

function stringField(record: Record<string, unknown> | null, ...keys: string[]): string | null {
  if (!record) return null
  for (const key of keys) {
    const value = record[key]
    if (typeof value === 'string' && value.length > 0) return value
  }
  return null
}

function isProbeName(name: string): boolean {
  return /^probe/i.test(name)
}

function isDecoyVerdict(payload: Record<string, unknown>): boolean {
  return payload.decoy === true || payload.isDecoy === true || payload.targetKind === 'decoy'
}

function verdictKey(event: LifecycleEvent, payload: Record<string, unknown>): string {
  return stringField(payload, 'findingId', 'id')
    ?? `${stringField(payload, 'vulnClass', 'class') ?? 'unknown'}#${event.seq}`
}

function verdictClass(payload: Record<string, unknown>): string {
  return stringField(payload, 'vulnClass', 'class') ?? 'unknown'
}

function ordinaryLeastSquaresSlope(points: Array<{ x: number; y: number }>): number {
  if (points.length < 2) return 0
  const meanX = points.reduce((sum, point) => sum + point.x, 0) / points.length
  const meanY = points.reduce((sum, point) => sum + point.y, 0) / points.length
  let covariance = 0
  let varianceX = 0
  for (const point of points) {
    covariance += (point.x - meanX) * (point.y - meanY)
    varianceX += (point.x - meanX) ** 2
  }
  return varianceX === 0 ? 0 : covariance / varianceX
}

function applyControl(
  confirmedKeys: Map<string, string>,
  control: TraceControlSummary | undefined,
): number | null {
  if (!control) return null
  if (Array.isArray(control.confirmedFindingIds)) {
    const baseline = new Set(control.confirmedFindingIds)
    return [...confirmedKeys.keys()].filter((key) => !baseline.has(key)).length
  }
  if (control.confirmedByClass) {
    const currentByClass = new Map<string, number>()
    for (const vulnClass of confirmedKeys.values()) {
      currentByClass.set(vulnClass, (currentByClass.get(vulnClass) ?? 0) + 1)
    }
    let delta = 0
    const classes = new Set([...currentByClass.keys(), ...Object.keys(control.confirmedByClass)])
    for (const vulnClass of classes) {
      delta += Math.max(0, (currentByClass.get(vulnClass) ?? 0) - (control.confirmedByClass[vulnClass] ?? 0))
    }
    return delta
  }
  if (typeof control.confirmed === 'number' && Number.isFinite(control.confirmed)) {
    return confirmedKeys.size - control.confirmed
  }
  return null
}

export function computeTraceMetrics(
  traceDir: string,
  control?: TraceControlSummary,
): { metrics: TraceMetrics; manifest: TraceManifest | null; issues: string[] } {
  const trace = readTrace(traceDir)
  const events: TraceEvent[] = trace.events
  const turns = events.filter((event): event is TurnEvent => event.type === 'turn')
  const toolResults = events.filter((event): event is ToolResultEvent => event.type === 'tool_result')
  const planners = events.filter((event): event is PlannerDecisionEvent => event.type === 'planner_decision')
  const lifecycles = events.filter((event): event is LifecycleEvent => event.type === 'lifecycle')

  const startedAtMs = trace.manifest?.startedAtMs ?? events[0]?.ts ?? 0
  const endedAtMs = trace.manifest?.endedAtMs ?? events.at(-1)?.ts ?? startedAtMs
  const spanMs = Math.max(0, endedAtMs - startedAtMs)
  const minutes = spanMs / 60_000

  // Confirmed verdicts and precision.
  const confirmedKeys = new Map<string, string>()
  const decoyConfirmedKeys = new Set<string>()
  for (const event of lifecycles) {
    if (event.kind !== 'verdict') continue
    const payload = event.payload ?? {}
    if (payload.status !== 'confirmed') continue
    const key = verdictKey(event, payload)
    if (isDecoyVerdict(payload)) {
      decoyConfirmedKeys.add(key)
      continue
    }
    confirmedKeys.set(key, verdictClass(payload))
  }

  const verifierFalsePositives = new Set<string>()
  const verifierDecoyFalsePositives = new Set<string>()
  for (const result of toolResults) {
    const feedback = payloadObject(result.verifierFeedback)
    if (!feedback) continue
    const falsePositive = feedback.falsePositive === true || feedback.verdict === 'false_positive'
    if (!falsePositive) continue
    const key = result.callId || `tool#${result.seq}`
    verifierFalsePositives.add(key)
    if (feedback.decoy === true || feedback.targetKind === 'decoy') verifierDecoyFalsePositives.add(key)
  }
  const decoyFalsePositives = new Set([...decoyConfirmedKeys, ...verifierDecoyFalsePositives]).size
  const precisionDenominator = confirmedKeys.size + decoyConfirmedKeys.size + verifierFalsePositives.size
  const precision = precisionDenominator === 0 ? 1 : confirmedKeys.size / precisionDenominator

  const deltaConfirmed = applyControl(confirmedKeys, control)

  // Signals vs specs.
  const signalIds = new Set<string>()
  const probedSignalIds = new Set<string>()
  for (const result of toolResults) {
    for (const factId of result.factIds ?? []) signalIds.add(factId)
    if (isProbeName(result.name)) {
      for (const factId of result.factIds ?? []) probedSignalIds.add(factId)
    }
  }
  const convertedSignals = [...signalIds].filter((factId) => probedSignalIds.has(factId)).length
  const signalToSpecConversion = signalIds.size === 0 ? 1 : convertedSignals / signalIds.size

  // Time to first probe (tool result or lifecycle probe lane).
  const probeTimestamps: number[] = []
  for (const result of toolResults) if (isProbeName(result.name)) probeTimestamps.push(result.ts)
  for (const event of lifecycles) {
    if (event.kind !== 'lane_start') continue
    const lane = stringField(event.payload, 'lane', 'name')
    if (lane && /^probe/i.test(lane)) probeTimestamps.push(event.ts)
  }
  const timeToFirstProbeMs = probeTimestamps.length > 0
    ? Math.max(0, Math.min(...probeTimestamps) - startedAtMs)
    : null

  // Assignment throughput. Clamp the elapsed window to one minute: very short traces would
  // otherwise extrapolate a single assignment to an absurd rate.
  const assignmentIds = new Set(turns.map((turn) => turn.assignmentId).filter((id) => id.length > 0))
  const effectiveMinutes = Math.max(minutes, 1)
  const assignmentsPer10Min = turns.length === 0 ? 0 : (assignmentIds.size / effectiveMinutes) * 10

  // Turn efficiency.
  const wastedTurns = turns.filter((turn) => (turn.toolCalls?.length ?? 0) === 0).length
  const wastedTurnRatio = turns.length === 0 ? 0 : wastedTurns / turns.length
  const httpRequests = toolResults.reduce((sum, result) => sum + (result.httpRequests ?? 0), 0)
  const batchingEfficiency = turns.length === 0 ? 0 : httpRequests / turns.length

  // Context growth.
  const contextGrowthSlope = ordinaryLeastSquaresSlope(
    turns.map((turn) => ({ x: turn.turnIdx, y: turn.usage?.input ?? 0 })),
  )

  // Spend.
  const turnCost = turns.reduce((sum, turn) => sum + (turn.usage?.costUsd ?? 0), 0)
  const plannerCost = planners.reduce((sum, planner) => sum + planner.costUsd, 0)
  const costUsd = turnCost + plannerCost
  const additive = deltaConfirmed ?? confirmedKeys.size
  const costPerAdditiveConfirmedUsd = additive > 0 ? costUsd / additive : null

  const metrics: TraceMetrics = {
    traceDir,
    events: events.length,
    confirmed: confirmedKeys.size,
    decoyFalsePositives,
    precision,
    deltaConfirmed,
    timeToFirstProbeMs,
    assignmentsPer10Min,
    signalToSpecConversion,
    wastedTurnRatio,
    batchingEfficiency,
    contextGrowthSlope,
    costPerAdditiveConfirmedUsd,
    totals: {
      turns: turns.length,
      toolResults: toolResults.length,
      assignments: assignmentIds.size,
      signals: signalIds.size,
      probedSignals: convertedSignals,
      httpRequests,
      costUsd,
      spanMs,
    },
  }
  return { metrics, manifest: trace.manifest, issues: trace.issues }
}

export function evaluateTraceGate(metrics: TraceMetrics): TraceGate {
  const precisionOk = metrics.precision >= 0.95
  const decoyOk = metrics.decoyFalsePositives === 0
  const throughputOk = metrics.signalToSpecConversion >= 0.8 || metrics.assignmentsPer10Min >= 15
  return { precisionOk, decoyOk, throughputOk, pass: precisionOk && decoyOk && throughputOk }
}

export function loadControlSummary(path: string): TraceControlSummary {
  const parsed: unknown = JSON.parse(readFileSync(path, 'utf8'))
  if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) {
    throw new Error('control summary must be a JSON object')
  }
  return parsed as TraceControlSummary
}

function formatPercent(value: number): string {
  return `${(value * 100).toFixed(1)}%`
}

function formatMetric(label: string, value: string): string {
  return `${label.padEnd(32)} ${value}`
}

export function formatMetricsTable(
  metrics: TraceMetrics,
  gate: TraceGate | null,
): string {
  const rows = [
    formatMetric('ΔConfirmed (additive)', metrics.deltaConfirmed === null ? 'n/a (no control)' : String(metrics.deltaConfirmed)),
    formatMetric('precision', `${formatPercent(metrics.precision)} (${metrics.confirmed} confirmed)`),
    formatMetric('decoy false positives', String(metrics.decoyFalsePositives)),
    formatMetric('time-to-first-probe', metrics.timeToFirstProbeMs === null ? 'n/a' : `${(metrics.timeToFirstProbeMs / 1000).toFixed(1)} s`),
    formatMetric('assignments / 10 min', metrics.assignmentsPer10Min.toFixed(1)),
    formatMetric('signal→spec conversion', formatPercent(metrics.signalToSpecConversion)),
    formatMetric('wasted-turn ratio', formatPercent(metrics.wastedTurnRatio)),
    formatMetric('batching (HTTP/LLM turn)', metrics.batchingEfficiency.toFixed(2)),
    formatMetric('context-growth slope', `${metrics.contextGrowthSlope.toFixed(0)} tok/turn`),
    formatMetric('$/additive confirmed', metrics.costPerAdditiveConfirmedUsd === null ? 'n/a' : `$${metrics.costPerAdditiveConfirmedUsd.toFixed(4)}`),
    formatMetric('events / turns / tools', `${metrics.events} / ${metrics.totals.turns} / ${metrics.totals.toolResults}`),
    formatMetric('span', `${(metrics.totals.spanMs / 1000).toFixed(1)} s`),
  ]
  if (gate) {
    rows.push('')
    rows.push(formatMetric('gate', gate.pass ? 'PASS' : 'FAIL'))
    rows.push(formatMetric('  precision ≥95%', gate.precisionOk ? 'ok' : 'FAIL'))
    rows.push(formatMetric('  zero decoy FP', gate.decoyOk ? 'ok' : 'FAIL'))
    rows.push(formatMetric('  signal≥80% or ≥15 asg/10m', gate.throughputOk ? 'ok' : 'FAIL'))
  }
  return rows.join('\n')
}

interface CliOptions {
  trace: string
  json: boolean
  gate: boolean
  controlPath: string | null
  controlConfirmed: number | null
}

function parseArgs(argv: string[]): CliOptions {
  const options: CliOptions = {
    trace: '',
    json: false,
    gate: false,
    controlPath: null,
    controlConfirmed: null,
  }
  for (let index = 0; index < argv.length; index += 1) {
    const arg = argv[index]
    switch (arg) {
      case '--trace':
        options.trace = argv[++index] ?? ''
        break
      case '--json':
        options.json = true
        break
      case '--gate':
        options.gate = true
        break
      case '--control':
        options.controlPath = argv[++index] ?? null
        break
      case '--control-confirmed': {
        const raw = argv[++index]
        const parsed = Number(raw)
        if (!Number.isFinite(parsed)) throw new Error(`invalid --control-confirmed: ${raw ?? ''}`)
        options.controlConfirmed = parsed
        break
      }
      case '-h':
      case '--help':
        printUsage()
        process.exit(0)
        break
      default:
        throw new Error(`unknown argument: ${arg}`)
    }
  }
  if (!options.trace) throw new Error('missing --trace <dir>')
  return options
}

function printUsage(): void {
  console.log(`Usage: node scripts/trace-metrics.ts --trace <dir> [--control <summary.json>] [--control-confirmed N] [--json] [--gate]`)
}

export function main(argv: string[]): number {
  let options: CliOptions
  try {
    options = parseArgs(argv)
  } catch (error) {
    console.error(error instanceof Error ? error.message : String(error))
    printUsage()
    return 2
  }
  const traceDir = resolve(options.trace)
  let control: TraceControlSummary | undefined
  try {
    if (options.controlPath) control = loadControlSummary(options.controlPath)
    else if (options.controlConfirmed !== null) control = { confirmed: options.controlConfirmed }
  } catch (error) {
    console.error(`failed to read control summary: ${error instanceof Error ? error.message : String(error)}`)
    return 2
  }
  let computed: ReturnType<typeof computeTraceMetrics>
  try {
    computed = computeTraceMetrics(traceDir, control)
  } catch (error) {
    console.error(`failed to read trace: ${error instanceof Error ? error.message : String(error)}`)
    return 2
  }
  const gate = evaluateTraceGate(computed.metrics)
  if (options.json) {
    console.log(JSON.stringify({
      traceDir,
      manifest: computed.manifest,
      metrics: computed.metrics,
      gate,
      issues: computed.issues,
    }, null, 2))
  } else {
    console.log(`trace: ${traceDir}`)
    if (computed.manifest) {
      console.log(`app: ${computed.manifest.app}  mode: ${computed.manifest.mode}  model: ${computed.manifest.model}  seed: ${String(computed.manifest.seed)}`)
    }
    console.log('')
    console.log(formatMetricsTable(computed.metrics, options.gate ? gate : null))
    if (computed.issues.length > 0) console.log(`\nissues: ${computed.issues.length} (run with --json for details)`)
  }
  if (options.gate && !gate.pass) return 1
  return 0
}

const invokedPath = process.argv[1] ? pathToFileURL(resolve(process.argv[1])).href : ''
if (invokedPath && import.meta.url === invokedPath) {
  process.exitCode = main(process.argv.slice(2))
}
