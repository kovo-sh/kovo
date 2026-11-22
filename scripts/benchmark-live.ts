/**
 * Live recall benchmark pipeline. Boots the lab server on loopback, then drives Guardian's
 * real engines generically: recon -> hypothesis formation -> probes -> replay-spec synthesis ->
 * Zero-LLM verification. Manifest answer keys are used only afterwards, for scoring.
 */
import { existsSync } from 'node:fs'
import { resolve } from 'node:path'
import { pathToFileURL } from 'node:url'
import { verifyReplaySpec, verifyReplaySpecInline } from '../src/server/replay-verifier.ts'
import type { ReplayVerificationResult } from '../src/server/replay-verifier.ts'
import type { BrokerExchangeResult } from '../src/server/broker.ts'
import type { InlineVerifyFeedback } from '../src/domain.ts'
import { selectVerifierBackend } from './benchmark-backend.ts'
import type { WorkerBackend } from '../src/server/worker-backend.ts'
import { createEngineEnv, discoverEndpoints } from './benchmark-env.ts'
import type { EngineEnv } from './benchmark-env.ts'
import { formHypotheses, needsCsrf, profileCaps, runHypothesis } from './benchmark-probes.ts'
import type { Hypothesis, HypothesisOutcome } from './benchmark-probes.ts'
import { compatibleClasses, endpointMatches, scoreManifest } from './benchmark-score.ts'
import type { ScoredOutcome } from './benchmark-score.ts'
import { synthesizeSpecs } from './benchmark-specs.ts'
import {
  BATCH_VERIFY_PROBE_CLASSES,
  applyBenchmarkClassCaps,
  classifyHypothesisConcurrency,
  computeSlowProbeAllowance,
  resolveBenchOrchestrationConfig,
  runBenchmarkSchedule,
  selectSlowProbeKeys,
  verificationBatches,
} from './benchmark-core.ts'
import type {
  AllPatchesVerification,
  BenchmarkManifest,
  BenchmarkOrchestrationConfig,
  BenchmarkOrchestrationOverrides,
  BenchmarkProfileMode,
  BenchmarkScheduledTask,
  BenchmarkSuiteName,
  PatchVerificationEntry,
  PatchVerificationSummary,
  TargetTrace,
} from './benchmark-core.ts'
import type { BenchmarkServerHandle, BenchmarkServerLauncher, VerifierBackendChoice } from './benchmark-recall.ts'

export interface LivePipelineArgs {
  suite: BenchmarkSuiteName
  manifest: BenchmarkManifest
  profileMode: BenchmarkProfileMode
  launcher?: BenchmarkServerLauncher
  verifierBackend: VerifierBackendChoice
  repoRootDir: string
  /** Env/CLI orchestration overrides; env vars supply anything omitted. */
  orchestration?: BenchmarkOrchestrationOverrides
}

/**
 * A target that the live pipeline actually confirmed, together with the exact synthesized
 * replay spec. Patch verification replays these specs against patched servers; it never
 * synthesizes new findings from the manifest.
 */
export interface ConfirmedFinding {
  /** Manifest challenge id this verdict is scored against (scoring/bookkeeping only). */
  id: string
  isDecoy: boolean
  /** Endpoint the confirming hypothesis ran against. */
  path: string
  probeClass: string
  spec: Record<string, unknown>
  /**
   * True when two targets could only be explained by the same spec (e.g. two distinct resolver
   * flaws behind one GraphQL endpoint whose evidence was not separable). Such findings are reported
   * for recall but are not used as patch fixed/regressed evidence.
   */
  ambiguousAttribution?: boolean
}

export interface LivePipelineOutcome {
  traces: TargetTrace[]
  findings: ConfirmedFinding[]
  totalCostUsd: number
  verifierBackend: string | null
  notes: string[]
}

export interface PatchRunResult {
  findings: ConfirmedFinding[]
  notes: string[]
}

export interface PatchReplayResult {
  verdict: string
  /** Every verdict observed for this finding, in attempt order. */
  verdicts?: string[]
  note?: string
}

/**
 * Test seams for patch verification. The default implementation launches real lab servers and
 * replays recorded specs through the Zero-LLM verifier; tests can substitute either half.
 */
export interface PatchVerificationHooks {
  /** Run the full pipeline with a patched id set and report what confirmed. */
  runFull?: (patchedIds: string[]) => Promise<PatchRunResult>
  /** Replay the given findings against a fresh server with `patchedIds` applied. Keyed by finding id. */
  replayAll?: (input: {
    findings: ConfirmedFinding[]
    patchedIds: string[]
    timeoutMs: number
    signal: AbortSignal
  }) => Promise<Map<string, PatchReplayResult>>
}

export interface PatchVerificationArgs {
  manifest: BenchmarkManifest
  profileMode?: BenchmarkProfileMode
  launcher?: BenchmarkServerLauncher
  verifierBackend?: VerifierBackendChoice
  repoRootDir?: string
  suite?: BenchmarkSuiteName
  /** Already-completed unpatched run; avoids paying for the baseline pipeline twice. */
  baseline?: Pick<LivePipelineOutcome, 'findings'> | null
  /** Max unrelated findings replayed per patch as an isolation check (default 4, 0 disables). */
  isolationSample?: number
  /** Orchestration knobs forwarded to the baseline/all-patches pipeline runs. */
  orchestration?: BenchmarkOrchestrationOverrides
  /** Wall-clock bound for one isolated patch retest (default 90s). */
  patchTimeoutMs?: number
  /** Wall-clock bound for the all-patches baseline-spec replay (default 10 min). */
  allPatchesTimeoutMs?: number
  hooks?: PatchVerificationHooks
}

export class PatchTimeoutError extends Error {
  constructor(label: string, ms: number) {
    super(`${label} timed out after ${ms} ms`)
    this.name = 'PatchTimeoutError'
  }
}

interface RawPersonaRecord {
  handle?: unknown
  name?: unknown
  roleLabel?: unknown
  role?: unknown
  authKind?: unknown
  secret?: unknown
  token?: unknown
  cookie?: unknown
  jwt?: unknown
  headerName?: unknown
  userId?: unknown
}

/**
 * Labs in this repo expose personas in two shapes: a handle-keyed map (`xben-25`) and an array of
 * `{handle, secret, roleLabel, userId}` records (held-out SaaS, matching its LabRunner seed format).
 * `createEngineEnv` consumes the map shape, so normalize both here rather than leaking the lab's
 * storage format into the engine environment.
 */
export function normalizePersonaMap(personas: unknown): BenchmarkServerHandle['personas'] {
  if (!personas) return {}
  if (!Array.isArray(personas)) return personas as BenchmarkServerHandle['personas']
  const out: BenchmarkServerHandle['personas'] = {}
  personas.forEach((raw, index) => {
    if (!raw || typeof raw !== 'object') return
    const rec = raw as RawPersonaRecord
    const handle = typeof rec.handle === 'string' ? rec.handle : typeof rec.name === 'string' ? rec.name : `persona_${index}`
    const secret = [rec.token, rec.jwt, rec.secret].find((v): v is string => typeof v === 'string' && v.length > 0)
    out[handle] = {
      ...(secret ? { token: secret } : {}),
      ...(typeof rec.cookie === 'string' ? { cookie: rec.cookie } : {}),
      ...(typeof rec.headerName === 'string' ? { headerName: rec.headerName } : {}),
      ...(typeof rec.roleLabel === 'string' ? { role: rec.roleLabel } : typeof rec.role === 'string' ? { role: rec.role } : {}),
      ...(typeof rec.userId === 'string' ? { userId: rec.userId } : {}),
    }
  })
  return out
}

function normalizeHandle(handle: BenchmarkServerHandle): BenchmarkServerHandle {
  return { ...handle, personas: normalizePersonaMap(handle.personas) }
}

async function importFirst(candidates: string[]): Promise<Record<string, unknown>> {
  for (const file of candidates) {
    if (existsSync(file)) return await import(pathToFileURL(file).href) as Record<string, unknown>
  }
  throw new Error(`Benchmark server module not found; looked for: ${candidates.join(', ')}`)
}

export async function resolveLauncher(suite: BenchmarkSuiteName, rootDir: string): Promise<BenchmarkServerLauncher> {
  if (suite === 'xben-25') {
    const mod = await importFirst([resolve(rootDir, 'benchmarks/xben-25/server.ts')])
    const start = mod.startXben25Server as ((o?: { host?: string; port?: number }) => Promise<BenchmarkServerHandle>) | undefined
    if (!start) throw new Error('benchmarks/xben-25/server.ts must export startXben25Server.')
    return () => start({ host: '127.0.0.1', port: 0 })
  }
  const dir = resolve(rootDir, 'local-lab/held-out-saas')
  const mod = await importFirst([resolve(dir, 'server.ts'), resolve(dir, 'server.mjs')])
  const start = mod.startHeldOutSaasServer as ((o?: { host?: string; port?: number; patchedIds?: string[] }) => Promise<BenchmarkServerHandle>) | undefined
  if (!start) throw new Error('local-lab/held-out-saas/server must export startHeldOutSaasServer.')
  return opts => start({ host: '127.0.0.1', port: 0, ...(opts?.patchedIds ? { patchedIds: opts.patchedIds } : {}) })
}

interface VerifyResult { verdict: string; feedback: InlineVerifyFeedback | null; replay: ReplayVerificationResult | null }

async function verifyWithProfile(
  env: EngineEnv, spec: Record<string, unknown>, backend: Awaited<ReturnType<typeof selectVerifierBackend>>['backend'],
  retries: number, onExchange: (ex: BrokerExchangeResult) => void, extraSignal?: AbortSignal,
): Promise<VerifyResult> {
  const signals = [env.controller.signal, AbortSignal.timeout(90_000)]
  if (extraSignal) signals.push(extraSignal)
  const base = {
    spec, broker: env.broker, canaryBroker: env.canaryBroker, backend, grant: env.grant, storage: env.storage, runId: env.runId,
    signal: AbortSignal.any(signals), onExchange: (ex: BrokerExchangeResult) => { onExchange(ex) },
  }
  if (retries <= 0) {
    const replay = await verifyReplaySpec(base)
    return { verdict: replay.verdict, feedback: null, replay }
  }
  let last: VerifyResult = { verdict: 'inconclusive', feedback: null, replay: null }
  for (let attempt = 1; attempt <= 1 + retries; attempt += 1) {
    const res = await verifyReplaySpecInline({ ...base, attemptCount: attempt, maxRetries: retries })
    last = { verdict: res.replay.verdict, feedback: res.feedback, replay: res.replay }
    if (res.replay.verdict === 'confirmed' || res.replay.verdict === 'dismissed') break
  }
  return last
}

type ExecutedOutcome = ScoredOutcome & { spec?: Record<string, unknown> }

interface ClassStat {
  hypotheses: number
  skipped: number
  requests: number
  signals: number
  confirmed: number
  ms: number
}

interface TaskResult {
  scored: ExecutedOutcome
}

async function execute(env: EngineEnv, args: LivePipelineArgs, notes: string[]): Promise<{ traces: TargetTrace[]; findings: ConfirmedFinding[]; backendKind: string }> {
  const caps = profileCaps(args.profileMode)
  const config: BenchmarkOrchestrationConfig = resolveBenchOrchestrationConfig(process.env, args.orchestration ?? {})
  const executeStarted = Date.now()
  const deadline = executeStarted + config.deadlineMs
  const verifier = await selectVerifierBackend(args.verifierBackend)
  const onExchange = (_ex: BrokerExchangeResult) => undefined

  const discoveryStarted = Date.now()
  const endpoints = await discoverEndpoints(env, caps, onExchange)
  const discoveryMs = Date.now() - discoveryStarted
  const plan = formHypotheses(endpoints, caps)
  const discoveredCount = plan.hypotheses.length
  const capped = applyBenchmarkClassCaps(plan.hypotheses, config.classCaps)
  const hypotheses = capped.kept
  notes.push(`Discovered ${endpoints.length} endpoints; formed ${discoveredCount} hypotheses; class caps kept ${hypotheses.length}.`)

  // Blind time-based SQLi is the only probe that deliberately sleeps on the target. Scale its
  // allowance with the candidate count, ranked by param/path plausibility, but execute the chosen
  // subset in plan order so stateful writes keep their positions.
  const slowCandidates = hypotheses.filter(h => h.probeClass === 'sqli_time_diff')
  const slowAllowance = computeSlowProbeAllowance(slowCandidates.length, config.slowProbes)
  const slowKeys = selectSlowProbeKeys(
    slowCandidates.map(h => ({
      key: h.key, path: h.endpoint.path, ...(h.param ? { param: h.param.name } : {}),
      ...(h.location ? { location: h.location } : {}), method: h.method,
    })),
    slowAllowance,
  )
  env.probeEnv.slowProbesLeft = slowAllowance

  const stats = new Map<string, ClassStat>()
  const statFor = (probeClass: string): ClassStat => {
    let stat = stats.get(probeClass)
    if (!stat) {
      stat = { hypotheses: 0, skipped: 0, requests: 0, signals: 0, confirmed: 0, ms: 0 }
      stats.set(probeClass, stat)
    }
    return stat
  }

  const signalledParams = new Set<string>()
  const budgetSkipped = new Set<string>()

  const runOne = async (hyp: Hypothesis): Promise<TaskResult | null> => {
    const stat = statFor(hyp.probeClass)
    if (Date.now() > deadline || env.requestsUsed() > config.maxRequests) {
      budgetSkipped.add(hyp.endpoint.path)
      stat.skipped += 1
      return null
    }
    const paramKey = `${hyp.endpoint.method}|${hyp.endpoint.path}|${hyp.param?.name ?? ''}`
    if (hyp.probeClass === 'sqli_time_diff') {
      // Boolean sibling always precedes the time probe in plan order; the scheduler enforces the
      // dependency, so this read is stable and never races a concurrent boolean probe.
      if (signalledParams.has(paramKey) || env.probeEnv.slowProbesLeft <= 0) {
        stat.skipped += 1
        return null
      }
      env.probeEnv.slowProbesLeft -= 1
    }

    const started = Date.now()
    const local = { requests: 0 }
    const watch = (ex: BrokerExchangeResult) => { local.requests += 1; onExchange(ex) }
    const outcome: HypothesisOutcome = await runHypothesis(hyp, env.probeEnv, watch)
    if (outcome.verdict === 'signal' && hyp.probeClass === 'sqli_boolean') signalledParams.add(paramKey)
    const scored: ExecutedOutcome = {
      path: hyp.endpoint.path, probeClass: hyp.probeClass, signal: outcome.verdict === 'signal', specSubmitted: false, confirmed: false,
      csrfRejected: outcome.csrfRejected, contextReset: outcome.contextReset, tierBlocked: outcome.tierBlocked,
      jqError: false, spaCatchall: false, skippedForBudget: false,
    }
    if (process.env.GUARDIAN_BENCH_DEBUG === '1') {
      notes.push(`[debug] ${hyp.probeClass} ${hyp.endpoint.method} ${hyp.endpoint.path} param=${hyp.param?.name ?? '-'}@${hyp.location ?? '-'} -> ${outcome.verdict}: ${(outcome.summary ?? outcome.error ?? '').slice(0, 140)} anomalies=${outcome.anomalies.map(a => String(a.type)).join(',')}`)
      if (outcome.verdict === 'signal') notes.push(`[debugjson] ${hyp.probeClass} ${hyp.endpoint.path} ${JSON.stringify(outcome.anomalies).slice(0, 900)} details=${JSON.stringify(outcome.details).slice(0, 500)}`)
    }

    const candidates = synthesizeSpecs(outcome, env.probeEnv).slice(0, 4)
    // Batch-verify only read-only hypotheses: their replay specs do not mutate target state and each
    // replay gets its own broker jar prefix. Confirm-on-first is preserved across ordered batches.
    const safety = classifyHypothesisConcurrency({
      probeClass: hyp.probeClass, method: hyp.method,
      ...(hyp.secondOrder ? { secondOrder: true } : {}),
      ...(hyp.browserEligible ? { browserEligible: true } : {}),
      ...(hyp.urlDomSink ? { urlDomSink: true } : {}),
      ...(needsCsrf(hyp) ? { csrfBound: true } : {}),
    })
    const verifyConcurrency = safety.parallelSafe && BATCH_VERIFY_PROBE_CLASSES.has(hyp.probeClass)
      ? Math.max(1, config.verifyConcurrency)
      : 1
    outer:
    for (const batch of verificationBatches(candidates, verifyConcurrency)) {
      const settled = await Promise.all(batch.map(async synth => {
        scored.specSubmitted = true
        scored.spec = synth.spec
        try {
          const res = await verifyWithProfile(env, synth.spec, verifier.backend, caps.inlineRetries, watch)
          return { synth, res }
        } catch (err) {
          notes.push(`verify error on ${hyp.endpoint.path} (${hyp.probeClass}): ${err instanceof Error ? err.message.slice(0, 120) : String(err)}`)
          return { synth, error: err }
        }
      }))
      for (const item of settled) {
        if ('error' in item) continue
        const res = item.res
        scored.jqError = scored.jqError || Boolean(res.feedback?.jqError)
        scored.spaCatchall = scored.spaCatchall || Boolean(res.feedback?.spaCatchallMatched)
        if (/blocked below Tier 3|requires explicit Tier 3/i.test(res.replay?.outcome.reason ?? '')) scored.tierBlocked = true
        if (process.env.GUARDIAN_BENCH_DEBUG === '1') notes.push(`[debugverify] ${item.synth.kind} ${hyp.endpoint.path} param=${hyp.param?.name ?? '-'} -> ${res.verdict}: ${(res.replay?.outcome.reason ?? res.replay?.outcome.observed ?? '').slice(0, 160)}`)
        if (res.verdict === 'confirmed') { scored.confirmed = true; break outer }
      }
    }

    stat.requests += local.requests
    stat.ms += Date.now() - started
    stat.signals += outcome.verdict === 'signal' ? 1 : 0
    if (scored.confirmed) {
      stat.confirmed += 1
      notes.push(`Confirmed: ${hyp.probeClass} ${hyp.method} ${hyp.endpoint.path} param=${hyp.param?.name ?? '-'} requests=${local.requests}`)
    }
    stat.hypotheses += 1
    if (process.env.GUARDIAN_BENCH_DEBUG === '1') notes.push(`[timing] ${hyp.probeClass} ${hyp.endpoint.method} ${hyp.endpoint.path} ${Date.now() - started}ms requests=${local.requests}`)
    return { scored }
  }

  const tasks: Array<BenchmarkScheduledTask<TaskResult | null>> = []
  const taskKeys = new Set(hypotheses.map(h => h.key))
  for (const hyp of hypotheses) {
    const stat = statFor(hyp.probeClass)
    if (hyp.probeClass === 'sqli_time_diff' && !slowKeys.has(hyp.key)) {
      stat.skipped += 1
      continue
    }
    const safety = classifyHypothesisConcurrency({
      probeClass: hyp.probeClass, method: hyp.method,
      ...(hyp.secondOrder ? { secondOrder: true } : {}),
      ...(hyp.browserEligible ? { browserEligible: true } : {}),
      ...(hyp.urlDomSink ? { urlDomSink: true } : {}),
      ...(needsCsrf(hyp) ? { csrfBound: true } : {}),
    })
    const siblingKey = hyp.probeClass === 'sqli_time_diff' ? hyp.key.replace(/^sqli_time_diff\|/, 'sqli_boolean|') : null
    const dependsOn = siblingKey && taskKeys.has(siblingKey) ? [siblingKey] : undefined
    tasks.push({
      key: hyp.key,
      parallelSafe: safety.parallelSafe && config.probeConcurrency > 1,
      ...(dependsOn ? { dependsOn } : {}),
      run: () => runOne(hyp),
    })
  }

  const results = await runBenchmarkSchedule(tasks, { concurrency: config.probeConcurrency })
  const executed = results.filter((r): r is TaskResult => r !== null).map(r => r.scored)

  // Per-class budget telemetry: request counts are per task (exchange-level) so they stay stable
  // under concurrency; broker audit units (used/cap) double-count allowed+observed.
  notes.push(`Orchestration: probeConcurrency=${config.probeConcurrency} verifyConcurrency=${config.verifyConcurrency} maxRequests=${config.maxRequests} deadlineMs=${config.deadlineMs} slowProbes=${slowAllowance}/${slowCandidates.length} discoveryMs=${discoveryMs}`)
  notes.push('Serial lanes: non-GET writes, second-order plants, browser/url-DOM XSS, cache deception, SSRF/XXE canaries, auth-protocol probes. Broker rate limit: 20 rps per origin.')
  if (capped.dropped.length) {
    const byClass = new Map<string, number>()
    for (const d of capped.dropped) byClass.set(d.probeClass, (byClass.get(d.probeClass) ?? 0) + 1)
    const summary = [...byClass.entries()].sort((a, b) => a[0].localeCompare(b[0])).map(([c, n]) => `${c}=${n}`).join(',')
    notes.push(`Class caps: dropped ${capped.dropped.length} hypotheses (${summary}).`)
  }
  for (const probeClass of [...stats.keys()].sort()) {
    const s = stats.get(probeClass)!
    notes.push(`Class stat: ${probeClass} hypotheses=${s.hypotheses} skipped=${s.skipped} requests=${s.requests} ms=${s.ms} signals=${s.signals} confirmed=${s.confirmed}`)
  }

  const traces = scoreManifest(args.manifest.challenges, {
    discoveredPaths: endpoints.map(e => e.path),
    outcomes: executed,
    encodingSkipPaths: plan.encodingSkips.map(s => s.path),
    budgetSkippedPaths: [...budgetSkipped],
  })
  notes.push(`Requests used: ${env.requestsUsed()} / ${config.maxRequests}; hypotheses=${discoveredCount}; executed=${executed.length}; budgetSkipped=${budgetSkipped.size}`)
  const executeWallMs = Math.max(1, Date.now() - executeStarted)
  const httpExchanges = Math.round(env.requestsUsed() / 2)
  notes.push(`Orchestration utilization: wallMs=${executeWallMs} httpExchanges≈${httpExchanges} effectiveRps=${(httpExchanges / (executeWallMs / 1000)).toFixed(1)}`)
  return { traces, findings: collectConfirmedFindings(args.manifest, executed, traces), backendKind: verifier.kind }
}

/**
 * Map scored confirmations back onto the exact specs that produced them. This is bookkeeping on
 * results the pipeline already produced; the manifest is not consulted to choose or shape requests.
 */
/** Prefer the probe class whose evidence type matches the target's vulnerability class. */
function probePreference(vulnClass: string, probeClass: string): number {
  const v = vulnClass.toLowerCase()
  const p = probeClass.toLowerCase()
  const wants = (...classes: string[]): boolean => classes.includes(p)
  if (/(bola|idor|bfla|authz|access|authorization)/.test(v)) {
    if (p === 'graphql_audit') return 0
    if (p === 'authz_matrix') return 1
  }
  if (/(graphql)/.test(v) && /(sqli|sql|injection)/.test(v) && wants('sqli_boolean', 'sqli_time_diff')) return 0
  if (/(sql|sqli|injection)/.test(v) && wants('sqli_boolean', 'sqli_time_diff')) return 0
  if (/(xss|stored|dom|browser)/.test(v) && wants('xss_context')) return 0
  if (/(race)/.test(v) && wants('race_burst')) return 0
  if (/(command|rce)/.test(v) && wants('command_injection')) return 0
  if (/(traversal)/.test(v) && wants('path_traversal_benign')) return 0
  if (/(ssrf)/.test(v) && wants('ssrf_canary')) return 0
  if (/(workflow|business)/.test(v) && wants('workflow_invariant')) return 0
  if (/(mass)/.test(v) && wants('mass_assignment')) return 0
  if (/(cache)/.test(v) && wants('cache_poison_deception')) return 0
  if (/(jwt|oauth|auth)/.test(v) && wants('auth_protocol_audit')) return 0
  if (/(xxe)/.test(v) && wants('xxe_canary')) return 0
  if (/(ssti|template)/.test(v) && wants('ssti_math')) return 0
  return 5
}

function collectConfirmedFindings(manifest: BenchmarkManifest, executed: readonly ExecutedOutcome[], traces: readonly TargetTrace[]): ConfirmedFinding[] {
  const byId = new Map(manifest.challenges.map(c => [c.id, c]))
  const seen = new Set<string>()
  const usedSpecs = new Set<string>()
  const out: ConfirmedFinding[] = []
  for (const trace of traces) {
    if (!trace.confirmed || seen.has(trace.id)) continue
    const challenge = byId.get(trace.id)
    if (!challenge) continue
    const candidates = executed.filter(o => o.confirmed && o.spec && endpointMatches(challenge.endpoint, o.path))
    // A spec is attributable to at most one target. Prefer an unused spec whose probe class is
    // compatible with this target; if every candidate was already claimed by another target on the
    // same endpoint, the evidence is genuinely shared and is marked ambiguous.
    const compatible = compatibleClasses(challenge.vulnClass)
    const ranked = candidates
      .filter(o => !compatible || compatible.includes(o.probeClass))
      .sort((a, b) => probePreference(challenge.vulnClass, a.probeClass) - probePreference(challenge.vulnClass, b.probeClass))
    const preferred = ranked.find(o => !usedSpecs.has(JSON.stringify(o.spec))) ??
      candidates.find(o => !usedSpecs.has(JSON.stringify(o.spec)))
    const match = preferred ?? ranked[0] ?? candidates[0]
    if (!match?.spec) continue
    seen.add(trace.id)
    const specKey = JSON.stringify(match.spec)
    const ambiguous = !preferred
    usedSpecs.add(specKey)
    out.push({
      id: trace.id, isDecoy: Boolean(challenge.isDecoy), path: match.path, probeClass: match.probeClass, spec: match.spec,
      ...(ambiguous ? { ambiguousAttribution: true } : {}),
    })
  }
  return out.sort((a, b) => a.id.localeCompare(b.id))
}

async function runPipelineWithPatches(args: LivePipelineArgs, patchedIds: string[]): Promise<LivePipelineOutcome> {
  if (process.env.GUARDIAN_ALLOW_LOCAL_LAB !== '1') {
    throw new Error('Live benchmark runs require GUARDIAN_ALLOW_LOCAL_LAB=1.')
  }
  const caps = profileCaps(args.profileMode)
  const launcher = args.launcher ?? await resolveLauncher(args.suite, args.repoRootDir)
  const handle = normalizeHandle(await launcher({ patchedIds }))
  const notes: string[] = []
  let env: EngineEnv | null = null
  try {
    env = await createEngineEnv(handle, caps, args.suite)
    const { traces, findings, backendKind } = await execute(env, args, notes)
    return { traces, findings, totalCostUsd: 0, verifierBackend: backendKind, notes }
  } finally {
    if (env) await env.cleanup()
    await handle.close()
  }
}

export async function runLivePipeline(args: LivePipelineArgs): Promise<LivePipelineOutcome> {
  return await runPipelineWithPatches(args, [])
}

// ---------------------------------------------------------------------------
// Patch verification
// ---------------------------------------------------------------------------

interface PatchGroup { patchId: string; vulnIds: string[] }

function patchGroups(manifest: BenchmarkManifest): PatchGroup[] {
  const groups = new Map<string, Set<string>>()
  for (const c of manifest.challenges) {
    if (c.isDecoy) continue
    const patchId = typeof c.patchId === 'string' ? c.patchId.trim() : ''
    if (!patchId) continue
    const set = groups.get(patchId) ?? new Set<string>()
    set.add(c.id)
    groups.set(patchId, set)
  }
  return [...groups.entries()]
    .map(([patchId, ids]) => ({ patchId, vulnIds: [...ids].sort() }))
    .sort((a, b) => a.patchId.localeCompare(b.patchId) || a.vulnIds.join(',').localeCompare(b.vulnIds.join(',')))
}

function withTimeout<T>(promise: Promise<T>, ms: number, label: string): Promise<T> {
  let timer: ReturnType<typeof setTimeout> | undefined
  const timeout = new Promise<never>((_resolve, reject) => {
    timer = setTimeout(() => reject(new PatchTimeoutError(label, ms)), Math.max(1, ms))
    timer.unref?.()
  })
  return Promise.race([promise, timeout]).finally(() => { if (timer) clearTimeout(timer) })
}

const isConfirmedish = (verdict: string | undefined): boolean => verdict === 'confirmed' || verdict === 'static_verified'

/**
 * A confirmed spec carries the origin of the server it was synthesized against. Patch verification
 * launches a fresh server on a new loopback port, so rebase every structural origin field before
 * replay; payload URLs (SSRF/webhook targets, XML bodies) are intentionally left untouched.
 */
export function rebaseSpecOrigin<T>(spec: T, origin: string): T {
  const structuralKeys = new Set([
    'pathAndQuery', 'method', 'id', 'role', 'kind', 'steps', 'controlStep', 'probeStep', 'uploadStep',
    'fetchStep', 'cleanupStep', 'postCheckStep', 'burst', 'request', 'fetchTarget', 'jsonBody', 'xmlTemplate',
    'graphqlQuery', 'headers',
  ])
  const walk = (value: unknown): unknown => {
    if (Array.isArray(value)) return value.map(walk)
    if (!value || typeof value !== 'object') return value
    const record = value as Record<string, unknown>
    const isStructural = Object.keys(record).some(key => structuralKeys.has(key))
    const out: Record<string, unknown> = {}
    for (const [key, child] of Object.entries(record)) {
      if (key === 'targetOrigin' && typeof child === 'string') out[key] = origin
      else if (key === 'origin' && typeof child === 'string' && isStructural) out[key] = origin
      else out[key] = walk(child)
    }
    return out
  }
  return walk(spec) as T
}

interface DefaultRuntime extends Required<Pick<PatchVerificationHooks, 'runFull' | 'replayAll'>> {}

function buildDefaultRuntime(liveArgs: LivePipelineArgs): DefaultRuntime {
  const caps = profileCaps(liveArgs.profileMode)
  let backendPromise: Promise<{ kind: string; backend: WorkerBackend }> | null = null
  const backend = () => {
    backendPromise ??= selectVerifierBackend(liveArgs.verifierBackend).then(v => ({ kind: v.kind, backend: v.backend as unknown as WorkerBackend }))
    return backendPromise
  }
  return {
    runFull: async patchedIds => {
      const outcome = await runPipelineWithPatches(liveArgs, patchedIds)
      return { findings: outcome.findings, notes: outcome.notes }
    },
    replayAll: async ({ findings, patchedIds, timeoutMs, signal }) => {
      const results = new Map<string, PatchReplayResult>()
      const launcher = liveArgs.launcher ?? await resolveLauncher(liveArgs.suite, liveArgs.repoRootDir)
      const handle = normalizeHandle(await launcher({ patchedIds }))
      let env: EngineEnv | null = null
      try {
        env = await createEngineEnv(handle, caps, liveArgs.suite)
        const { backend: worker } = await backend()
        const internal = AbortSignal.any([signal, AbortSignal.timeout(timeoutMs)])
        for (const finding of findings) {
          if (internal.aborted) {
            results.set(finding.id, { verdict: 'inconclusive', verdicts: ['inconclusive'], note: 'patch retest timed out before replay' })
            continue
          }
          const spec = rebaseSpecOrigin(finding.spec, env.probeEnv.origin)
          const verdicts: string[] = []
          let verdict = 'inconclusive'
          let note: string | undefined
          try {
            const res = await verifyWithProfile(env, spec, worker, caps.inlineRetries, () => undefined, internal)
            verdict = res.verdict
            verdicts.push(verdict)
            if (res.replay?.outcome.reason) note = res.replay.outcome.reason
            if (verdict === 'inconclusive' && !internal.aborted) {
              // One bounded extra attempt for a spec that neither confirmed nor dismissed.
              const retry = await verifyWithProfile(env, spec, worker, caps.inlineRetries, () => undefined, internal)
              verdict = retry.verdict
              verdicts.push(verdict)
              if (retry.replay?.outcome.reason) note = retry.replay.outcome.reason
            }
          } catch (err) {
            verdict = 'error'
            verdicts.push('error')
            note = err instanceof Error ? err.message.slice(0, 160) : String(err).slice(0, 160)
          }
          results.set(finding.id, { verdict, verdicts, ...(note ? { note } : {}) })
        }
        return results
      } finally {
        if (env) await env.cleanup()
        await handle.close()
      }
    },
  }
}

function pickIsolation(baseline: readonly ConfirmedFinding[], exclude: ReadonlySet<string>, limit: number): ConfirmedFinding[] {
  if (limit <= 0) return []
  return baseline
    .filter(f => !f.isDecoy && !exclude.has(f.id))
    .sort((a, b) => a.id.localeCompare(b.id) || a.path.localeCompare(b.path))
    .slice(0, limit)
}

/**
 * Verify that each isolated lab patch makes its confirmed finding stop confirming, without
 * disturbing unrelated findings, then run one all-patches-applied pass.
 *
 * The baseline is a real, unpatched pipeline run (either supplied by the caller or executed
 * here). Per-patch retests replay the exact confirmed specs on a fresh server that has only
 * that one patch applied. Nothing here reads the manifest to decide what to request.
 */
export async function verifyPatchesLive(args: PatchVerificationArgs): Promise<PatchVerificationSummary> {
  const started = Date.now()
  const profileMode: BenchmarkProfileMode = args.profileMode ?? 'v4-full'
  const suite: BenchmarkSuiteName = args.suite ?? 'held-out-saas'
  const verifierBackend: VerifierBackendChoice = args.verifierBackend ?? 'auto'
  const repoRootDir = args.repoRootDir ?? resolve(import.meta.dirname, '..')
  const patchTimeoutMs = args.patchTimeoutMs ?? Number(process.env.GUARDIAN_BENCH_PATCH_TIMEOUT_MS ?? 90_000)
  const allPatchesTimeoutMs = args.allPatchesTimeoutMs ?? Number(process.env.GUARDIAN_BENCH_ALLPATCH_TIMEOUT_MS ?? 10 * 60_000)
  const isolationSample = args.isolationSample ?? Number(process.env.GUARDIAN_BENCH_PATCH_ISOLATION ?? 4)

  if (process.env.GUARDIAN_ALLOW_LOCAL_LAB !== '1') {
    return {
      attempted: 0, fixed: 0, reproducedBefore: 0, perPatch: [], durationMs: Date.now() - started,
      skippedReason: 'Patch verification requires GUARDIAN_ALLOW_LOCAL_LAB=1.',
    }
  }

  const groups = patchGroups(args.manifest)
  if (!groups.length) {
    return {
      attempted: 0, fixed: 0, reproducedBefore: 0, perPatch: [], durationMs: Date.now() - started,
      skippedReason: 'Manifest has no non-decoy challenge with a patchId; nothing to verify.',
    }
  }

  const liveArgs: LivePipelineArgs = {
    suite, manifest: args.manifest, profileMode, verifierBackend, repoRootDir,
    ...(args.launcher ? { launcher: args.launcher } : {}),
    ...(args.orchestration ? { orchestration: args.orchestration } : {}),
  }
  const defaults = buildDefaultRuntime(liveArgs)
  const hooks = args.hooks ?? {}
  const runtime = {
    runFull: hooks.runFull ?? defaults.runFull,
    replayAll: hooks.replayAll ?? defaults.replayAll,
  }

  // 1. Reproduction baseline: real unpatched run, unless the caller already has one.
  let baselineFindings: ConfirmedFinding[]
  if (args.baseline) {
    baselineFindings = [...args.baseline.findings].sort((a, b) => a.id.localeCompare(b.id))
  } else {
    try {
      const baseline = await withTimeout(runtime.runFull([]), allPatchesTimeoutMs, 'baseline pipeline')
      baselineFindings = [...baseline.findings].sort((a, b) => a.id.localeCompare(b.id))
    } catch (err) {
      return {
        attempted: 0, fixed: 0, reproducedBefore: 0, perPatch: [], durationMs: Date.now() - started,
        skippedReason: `Baseline pipeline failed; no patch verification attempted: ${err instanceof Error ? err.message : String(err)}`,
      }
    }
  }

  const findingById = new Map<string, ConfirmedFinding>()
  for (const f of baselineFindings) if (!findingById.has(f.id)) findingById.set(f.id, f)
  const ambiguousIds = new Set(baselineFindings.filter(f => !f.isDecoy && f.ambiguousAttribution).map(f => f.id))
  const decoyFalsePositivesBefore = new Set(baselineFindings.filter(f => f.isDecoy).map(f => f.id)).size

  const perPatch: PatchVerificationEntry[] = []
  let reproducedBefore = 0
  let fixed = 0

  for (const group of groups) {
    const label = group.vulnIds.join(',')
    const allTargets = group.vulnIds.map(id => findingById.get(id)).filter((f): f is ConfirmedFinding => Boolean(f))
    const targets = allTargets.filter(f => !f.ambiguousAttribution)
    const entry: PatchVerificationEntry = {
      id: group.vulnIds[0] ?? group.patchId,
      patchId: group.patchId,
      vulnId: label,
      before: 'not_confirmed',
      after: 'not_run',
      fixed: false,
      reproducedBefore: false,
      fixedAfter: false,
      verdicts: [],
      isolationChecked: 0,
      isolationPreserved: 0,
      isolationLost: [],
      notes: [],
    }
    if (!targets.length) {
      if (allTargets.length > 0) {
        entry.before = 'confirmed_ambiguous'
        entry.notes?.push('Only evidence for this target was shared with another target on the same endpoint (attribution ambiguous); it is not counted as fixed or regressed.')
      } else {
        entry.notes?.push('Not confirmed by the baseline pipeline, so this patch could not be retested.')
      }
      perPatch.push(entry)
      continue
    }
    reproducedBefore += 1
    entry.before = 'confirmed'
    entry.reproducedBefore = true

    const targetIds = new Set(group.vulnIds)
    const isolation = pickIsolation(baselineFindings, targetIds, isolationSample)
    const toReplay = [...targets, ...isolation]

    const controller = new AbortController()
    const timer = setTimeout(() => controller.abort(), patchTimeoutMs)
    timer.unref?.()
    let results: Map<string, PatchReplayResult>
    try {
      results = await withTimeout(
        runtime.replayAll({ findings: toReplay, patchedIds: [group.patchId], timeoutMs: patchTimeoutMs, signal: controller.signal }),
        patchTimeoutMs + 1_000,
        `patch ${group.patchId} retest`,
      )
    } catch (err) {
      const timeout = err instanceof PatchTimeoutError
      entry.after = timeout ? 'timeout' : 'error'
      entry.verdicts = [entry.after]
      entry.notes?.push(`${timeout ? 'Timed out' : 'Retest failed'}: ${err instanceof Error ? err.message.slice(0, 200) : String(err)}`)
      perPatch.push(entry)
      continue
    } finally {
      clearTimeout(timer)
    }

    const targetVerdicts: string[] = []
    let stillConfirming = false
    for (const target of targets) {
      const res = results.get(target.id)
      if (!res) {
        targetVerdicts.push('missing')
        entry.notes?.push(`No replay verdict returned for ${target.id}.`)
        continue
      }
      targetVerdicts.push(...(res.verdicts?.length ? res.verdicts : [res.verdict]))
      if (isConfirmedish(res.verdict)) stillConfirming = true
      if (res.note) entry.notes?.push(`${target.id}: ${res.note}`)
    }
    entry.verdicts = targetVerdicts
    entry.after = targetVerdicts.at(-1) ?? 'inconclusive'
    const inconclusiveOnly = targetVerdicts.length > 0 &&
      targetVerdicts.every(v => !['error', 'missing', 'timeout'].includes(v))
    entry.fixedAfter = !stillConfirming && inconclusiveOnly
    entry.fixed = Boolean(entry.reproducedBefore && entry.fixedAfter)
    if (entry.fixed) fixed += 1

    let preserved = 0
    for (const iso of isolation) {
      const res = results.get(iso.id)
      if (res && isConfirmedish(res.verdict)) preserved += 1
      else entry.isolationLost?.push(iso.id)
    }
    entry.isolationChecked = isolation.length
    entry.isolationPreserved = preserved
    if (entry.isolationLost?.length) {
      entry.notes?.push(`Isolation check: ${entry.isolationLost.join(', ')} no longer confirmed under patch ${group.patchId}.`)
    }
    if (entry.fixedAfter && entry.verdicts?.includes('inconclusive')) {
      entry.notes?.push('Patched retest was inconclusive (not confirmed); counted as fixed per patch-retest semantics.')
    }
    perPatch.push(entry)
  }

  // 2. All patches applied: replay the baseline-attributed specs as the evidence of record.
  //
  // A fresh pipeline pass is NOT used to decide whether a patched vuln regressed: it re-synthesises
  // specs from the patched surface and can credit an always-on surface (e.g. GraphQL introspection)
  // to a challenge whose planted flaw is actually gone. Replaying the exact baseline specs keeps the
  // all-patches verdict comparable to the per-patch retests.
  const allPatchIds = groups.map(g => g.patchId).sort()
  const allPatches: AllPatchesVerification = {
    patchIds: allPatchIds,
    attempted: false,
    stillConfirming: [],
    newlyConfirming: [],
    ambiguous: [...ambiguousIds].sort(),
    decoyFalsePositivesBefore,
    decoyFalsePositivesAfter: 0,
    verdict: 'inconclusive',
    notes: [],
  }
  if (baselineFindings.length === 0) {
    allPatches.attempted = true
    allPatches.verdict = 'fixed'
    allPatches.notes.push('No confirmed baseline findings to replay; nothing for the all-patches pass to re-confirm.')
  } else {
    const allController = new AbortController()
    const allTimer = setTimeout(() => allController.abort(), allPatchesTimeoutMs)
    allTimer.unref?.()
    try {
      const results = await withTimeout(
        runtime.replayAll({
          findings: baselineFindings,
          patchedIds: allPatchIds,
          timeoutMs: allPatchesTimeoutMs,
          signal: allController.signal,
        }),
        allPatchesTimeoutMs + 1_000,
        'all-patches baseline spec replay',
      )
      allPatches.attempted = true
      const still: string[] = []
      const decoyStill: string[] = []
      let dismissed = 0
      let failed = 0
      let replayed = 0
      for (const finding of baselineFindings) {
        const res = results.get(finding.id)
        const verdict = res?.verdict ?? 'missing'
        const confirmed = isConfirmedish(res?.verdict)
        if (finding.isDecoy) {
          if (confirmed) decoyStill.push(finding.id)
          continue
        }
        if (finding.ambiguousAttribution) continue
        replayed += 1
        if (confirmed) {
          still.push(finding.id)
          if (res?.note) allPatches.notes.push(`${finding.id}: ${res.note}`)
        } else if (['error', 'missing', 'timeout'].includes(verdict)) {
          failed += 1
          allPatches.notes.push(`${finding.id}: all-patches replay ${verdict}${res?.note ? ` (${res.note})` : ''}`)
        } else {
          dismissed += 1
        }
      }
      allPatches.replayed = replayed
      allPatches.dismissed = dismissed
      allPatches.stillConfirming = still.sort()
      allPatches.decoyFalsePositivesAfter = decoyStill.length
      // Regressed only on genuine baseline-spec re-confirmation. Transport failures are inconclusive,
      // not proof that the patch failed.
      allPatches.verdict = still.length > 0 ? 'regressed' : failed > 0 ? 'inconclusive' : 'fixed'
      if (still.length) {
        allPatches.notes.push(`Baseline specs still confirming with all patches applied: ${still.sort().join(', ')}.`)
      }
      if (decoyStill.length) {
        allPatches.notes.push(`Baseline decoy false-positive specs still confirmed after patches: ${decoyStill.sort().join(', ')} (decoys have no patch by design).`)
      }
      if (ambiguousIds.size > 0) {
        allPatches.notes.push(`Attribution ambiguous (shared evidence, excluded from patch verdict): ${[...ambiguousIds].sort().join(', ')}.`)
      }
      allPatches.notes.push('All-patches verdict is based on replaying baseline-attributed specs; a fresh pipeline pass is not used as patch evidence.')
    } catch (err) {
      allPatches.verdict = 'inconclusive'
      allPatches.notes.push(`All-patches baseline spec replay did not complete: ${err instanceof Error ? err.message.slice(0, 200) : String(err)}`)
    } finally {
      clearTimeout(allTimer)
    }
  }

  // Optional regression discovery: a fresh all-patched pipeline may surface new probe classes. Its
  // findings are NEVER used to mark a baseline vuln as still-confirming; only ids with no baseline
  // attribution are reported as newly confirming, and same-id findings are informational.
  if (allPatches.attempted && process.env.GUARDIAN_BENCH_ALLPATCH_FRESH === '1') {
    try {
      const fresh = await withTimeout(runtime.runFull(allPatchIds), allPatchesTimeoutMs, 'all-patches discovery pass')
      const baselineIds = new Set(baselineFindings.map(f => f.id))
      const freshVulns = fresh.findings.filter(f => !f.isDecoy)
      const newIds = [...new Set(freshVulns.map(f => f.id).filter(id => !baselineIds.has(id) && !ambiguousIds.has(id)))].sort()
      allPatches.newlyConfirming = newIds
      const reused = [...new Set(freshVulns.map(f => f.id).filter(id => baselineIds.has(id)))].sort()
      if (reused.length) {
        allPatches.notes.push(`Fresh pass also re-synthesised specs for baseline targets (${reused.join(', ')}); ignored for the verdict because baseline specs are the evidence of record.`)
      }
      if (newIds.length) {
        allPatches.notes.push(`Fresh pass surfaced findings with no baseline attribution: ${newIds.join(', ')} (reported, never counted as still-confirming).`)
      }
      const freshDecoys = fresh.findings.filter(f => f.isDecoy).map(f => f.id).sort()
      if (freshDecoys.length) {
        allPatches.notes.push(`Fresh pass decoy false positives: ${freshDecoys.join(', ')} (reported separately).`)
      }
    } catch (err) {
      allPatches.notes.push(`Optional fresh discovery pass did not complete: ${err instanceof Error ? err.message.slice(0, 160) : String(err)}`)
    }
  }

  const summary: PatchVerificationSummary = {
    attempted: groups.length,
    fixed,
    reproducedBefore,
    perPatch,
    allPatches,
    decoyFalsePositivesBefore,
    decoyFalsePositivesAfter: allPatches.attempted ? allPatches.decoyFalsePositivesAfter : undefined,
    durationMs: Date.now() - started,
  }
  return summary
}

export type { Hypothesis }
