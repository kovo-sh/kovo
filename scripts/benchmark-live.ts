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
import { createEngineEnv, discoverEndpoints } from './benchmark-env.ts'
import type { EngineEnv } from './benchmark-env.ts'
import { formHypotheses, profileCaps, runHypothesis } from './benchmark-probes.ts'
import type { Hypothesis, HypothesisOutcome } from './benchmark-probes.ts'
import { scoreManifest } from './benchmark-score.ts'
import type { ScoredOutcome } from './benchmark-score.ts'
import { synthesizeSpec } from './benchmark-specs.ts'
import type {
  BenchmarkManifest,
  BenchmarkProfileMode,
  BenchmarkSuiteName,
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
}

export interface LivePipelineOutcome {
  traces: TargetTrace[]
  totalCostUsd: number
  verifierBackend: string | null
  notes: string[]
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
  retries: number, onExchange: (ex: BrokerExchangeResult) => void,
): Promise<VerifyResult> {
  const base = {
    spec, broker: env.broker, canaryBroker: env.canaryBroker, backend, grant: env.grant, storage: env.storage, runId: env.runId,
    signal: AbortSignal.any([env.controller.signal, AbortSignal.timeout(90_000)]), onExchange: (ex: BrokerExchangeResult) => { onExchange(ex) },
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

async function execute(env: EngineEnv, args: LivePipelineArgs, notes: string[]): Promise<{ traces: TargetTrace[]; backendKind: string }> {
  const caps = profileCaps(args.profileMode)
  const deadline = Date.now() + Number(process.env.GUARDIAN_BENCH_DEADLINE_MS ?? 8 * 60_000)
  const verifier = await selectVerifierBackend(args.verifierBackend)
  const onExchange = (_ex: BrokerExchangeResult) => undefined

  const endpoints = await discoverEndpoints(env, caps, onExchange)
  const plan = formHypotheses(endpoints, caps)
  notes.push(`Discovered ${endpoints.length} endpoints; formed ${plan.hypotheses.length} hypotheses.`)

  const signalledParams = new Set<string>()
  const outcomes: ScoredOutcome[] = []
  const budgetSkipped = new Set<string>()
  const maxRequests = 3800
  for (const hyp of plan.hypotheses) {
    const paramKey = `${hyp.endpoint.method}|${hyp.endpoint.path}|${hyp.param?.name ?? ''}`
    const overBudget = Date.now() > deadline || env.requestsUsed() > maxRequests
    if (overBudget) { budgetSkipped.add(hyp.endpoint.path); continue }
    if (hyp.probeClass === 'sqli_time_diff' && (signalledParams.has(paramKey) || env.probeEnv.slowProbesLeft <= 0)) continue
    if (hyp.probeClass === 'sqli_time_diff') env.probeEnv.slowProbesLeft -= 1

    const outcome: HypothesisOutcome = await runHypothesis(hyp, env.probeEnv, onExchange)
    if (outcome.verdict === 'signal' && hyp.probeClass === 'sqli_boolean') signalledParams.add(paramKey)
    const scored: ScoredOutcome = {
      path: hyp.endpoint.path, probeClass: hyp.probeClass, signal: outcome.verdict === 'signal', specSubmitted: false, confirmed: false,
      csrfRejected: outcome.csrfRejected, contextReset: outcome.contextReset, tierBlocked: outcome.tierBlocked,
      jqError: false, spaCatchall: false, skippedForBudget: false,
    }
    const synth = synthesizeSpec(outcome, env.probeEnv)
    if (synth) {
      scored.specSubmitted = true
      try {
        const res = await verifyWithProfile(env, synth.spec, verifier.backend, caps.inlineRetries, onExchange)
        scored.confirmed = res.verdict === 'confirmed'
        scored.jqError = Boolean(res.feedback?.jqError)
        scored.spaCatchall = Boolean(res.feedback?.spaCatchallMatched)
        if (/blocked below Tier 3|requires explicit Tier 3/i.test(res.replay?.outcome.reason ?? '')) scored.tierBlocked = true
      } catch (err) {
        notes.push(`verify error on ${hyp.endpoint.path} (${hyp.probeClass}): ${err instanceof Error ? err.message.slice(0, 120) : String(err)}`)
      }
    }
    outcomes.push(scored)
  }
  const traces = scoreManifest(args.manifest.challenges, {
    discoveredPaths: endpoints.map(e => e.path),
    outcomes,
    encodingSkipPaths: plan.encodingSkips.map(s => s.path),
    budgetSkippedPaths: [...budgetSkipped],
  })
  return { traces, backendKind: verifier.kind }
}

export async function runLivePipeline(args: LivePipelineArgs): Promise<LivePipelineOutcome> {
  if (process.env.GUARDIAN_ALLOW_LOCAL_LAB !== '1') {
    throw new Error('Live benchmark runs require GUARDIAN_ALLOW_LOCAL_LAB=1.')
  }
  const caps = profileCaps(args.profileMode)
  const launcher = args.launcher ?? await resolveLauncher(args.suite, args.repoRootDir)
  const handle = await launcher({})
  const notes: string[] = []
  let env: EngineEnv | null = null
  try {
    env = await createEngineEnv(handle, caps, args.suite)
    const { traces, backendKind } = await execute(env, args, notes)
    return { traces, totalCostUsd: 0, verifierBackend: backendKind, notes }
  } finally {
    if (env) await env.cleanup()
    await handle.close()
  }
}

export async function verifyPatchesLive(_args: {
  manifest: BenchmarkManifest
  profileMode?: BenchmarkProfileMode
  launcher?: BenchmarkServerLauncher
  verifierBackend?: VerifierBackendChoice
  repoRootDir?: string
}): Promise<PatchVerificationSummary> {
  return { attempted: 0, fixed: 0, reproducedBefore: 0, perPatch: [], skippedReason: 'Patch verification is not implemented yet.' }
}

export type { Hypothesis }
