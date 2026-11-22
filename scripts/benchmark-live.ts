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
import { formHypotheses, profileCaps, runHypothesis } from './benchmark-probes.ts'
import type { Hypothesis, HypothesisOutcome } from './benchmark-probes.ts'
import { endpointMatches, scoreManifest } from './benchmark-score.ts'
import type { ScoredOutcome } from './benchmark-score.ts'
import { synthesizeSpecs } from './benchmark-specs.ts'
import type {
  AllPatchesVerification,
  BenchmarkManifest,
  BenchmarkProfileMode,
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
  /** Wall-clock bound for one isolated patch retest (default 90s). */
  patchTimeoutMs?: number
  /** Wall-clock bound for the all-patches-applied pipeline pass (default 10 min). */
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

async function execute(env: EngineEnv, args: LivePipelineArgs, notes: string[]): Promise<{ traces: TargetTrace[]; findings: ConfirmedFinding[]; backendKind: string }> {
  const caps = profileCaps(args.profileMode)
  const deadline = Date.now() + Number(process.env.GUARDIAN_BENCH_DEADLINE_MS ?? 8 * 60_000)
  const verifier = await selectVerifierBackend(args.verifierBackend)
  const onExchange = (_ex: BrokerExchangeResult) => undefined

  const endpoints = await discoverEndpoints(env, caps, onExchange)
  const plan = formHypotheses(endpoints, caps)
  notes.push(`Discovered ${endpoints.length} endpoints; formed ${plan.hypotheses.length} hypotheses.`)

  const signalledParams = new Set<string>()
  const executed: ExecutedOutcome[] = []
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
    for (const synth of candidates) {
      scored.specSubmitted = true
      scored.spec = synth.spec
      try {
        const res = await verifyWithProfile(env, synth.spec, verifier.backend, caps.inlineRetries, onExchange)
        scored.jqError = Boolean(res.feedback?.jqError)
        scored.spaCatchall = Boolean(res.feedback?.spaCatchallMatched)
        if (/blocked below Tier 3|requires explicit Tier 3/i.test(res.replay?.outcome.reason ?? '')) scored.tierBlocked = true
        if (process.env.GUARDIAN_BENCH_DEBUG === '1') notes.push(`[debugverify] ${synth.kind} ${hyp.endpoint.path} param=${hyp.param?.name ?? '-'} -> ${res.verdict}: ${(res.replay?.outcome.reason ?? res.replay?.outcome.observed ?? '').slice(0, 160)}`)
        if (res.verdict === 'confirmed') { scored.confirmed = true; break }
      } catch (err) {
        notes.push(`verify error on ${hyp.endpoint.path} (${hyp.probeClass}): ${err instanceof Error ? err.message.slice(0, 120) : String(err)}`)
      }
    }
    executed.push(scored)
  }
  const traces = scoreManifest(args.manifest.challenges, {
    discoveredPaths: endpoints.map(e => e.path),
    outcomes: executed,
    encodingSkipPaths: plan.encodingSkips.map(s => s.path),
    budgetSkippedPaths: [...budgetSkipped],
  })
  return { traces, findings: collectConfirmedFindings(args.manifest, executed, traces), backendKind: verifier.kind }
}

/**
 * Map scored confirmations back onto the exact specs that produced them. This is bookkeeping on
 * results the pipeline already produced; the manifest is not consulted to choose or shape requests.
 */
function collectConfirmedFindings(manifest: BenchmarkManifest, executed: readonly ExecutedOutcome[], traces: readonly TargetTrace[]): ConfirmedFinding[] {
  const byId = new Map(manifest.challenges.map(c => [c.id, c]))
  const seen = new Set<string>()
  const out: ConfirmedFinding[] = []
  for (const trace of traces) {
    if (!trace.confirmed || seen.has(trace.id)) continue
    const challenge = byId.get(trace.id)
    if (!challenge) continue
    const candidates = executed.filter(o => o.confirmed && o.spec && endpointMatches(challenge.endpoint, o.path))
    const match = candidates.find(o => !trace.probeClass || o.probeClass === trace.probeClass) ?? candidates[0]
    if (!match?.spec) continue
    seen.add(trace.id)
    out.push({ id: trace.id, isDecoy: Boolean(challenge.isDecoy), path: match.path, probeClass: match.probeClass, spec: match.spec })
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
  const baselineVulnIds = new Set(baselineFindings.filter(f => !f.isDecoy).map(f => f.id))
  const decoyFalsePositivesBefore = new Set(baselineFindings.filter(f => f.isDecoy).map(f => f.id)).size

  const perPatch: PatchVerificationEntry[] = []
  let reproducedBefore = 0
  let fixed = 0

  for (const group of groups) {
    const label = group.vulnIds.join(',')
    const targets = group.vulnIds.map(id => findingById.get(id)).filter((f): f is ConfirmedFinding => Boolean(f))
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
      entry.notes?.push('Not confirmed by the baseline pipeline, so this patch could not be retested.')
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

  // 2. All patches applied: a fresh full pipeline pass must re-confirm nothing and keep decoys clean.
  const allPatchIds = groups.map(g => g.patchId).sort()
  const allPatches: AllPatchesVerification = {
    patchIds: allPatchIds,
    attempted: false,
    stillConfirming: [],
    newlyConfirming: [],
    decoyFalsePositivesBefore,
    decoyFalsePositivesAfter: decoyFalsePositivesBefore,
    verdict: 'inconclusive',
    notes: [],
  }
  try {
    const all = await withTimeout(runtime.runFull(allPatchIds), allPatchesTimeoutMs, 'all-patches pipeline')
    allPatches.attempted = true
    const allVulnIds = new Set(all.findings.filter(f => !f.isDecoy).map(f => f.id))
    const allDecoyIds = new Set(all.findings.filter(f => f.isDecoy).map(f => f.id))
    allPatches.stillConfirming = [...baselineVulnIds].filter(id => allVulnIds.has(id)).sort()
    allPatches.newlyConfirming = [...allVulnIds].filter(id => !baselineVulnIds.has(id)).sort()
    allPatches.decoyFalsePositivesAfter = allDecoyIds.size
    allPatches.verdict = allPatches.stillConfirming.length === 0 && allDecoyIds.size === 0 ? 'fixed' : 'regressed'
    if (all.notes.length) allPatches.notes.push(...all.notes.slice(0, 5))
    if (allPatches.stillConfirming.length) {
      allPatches.notes.push(`Still confirming with all patches applied: ${allPatches.stillConfirming.join(', ')}.`)
    }
    if (allDecoyIds.size) {
      allPatches.notes.push(`Decoy false positives after all patches: ${[...allDecoyIds].sort().join(', ')} (decoys have no patch by design).`)
    }
    if (allPatches.newlyConfirming.length) {
      allPatches.notes.push(`Newly confirming (not seen at baseline): ${allPatches.newlyConfirming.join(', ')}.`)
    }
  } catch (err) {
    allPatches.verdict = 'inconclusive'
    allPatches.notes.push(`All-patches pass did not complete: ${err instanceof Error ? err.message.slice(0, 200) : String(err)}`)
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
