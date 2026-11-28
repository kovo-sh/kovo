/**
 * Track B Cut 1 — lightweight single-turn closed-loop planner over the pure-fact World Graph.
 *
 * Agentic rounds make exactly one tool-free `providerPool` + `models.stream` call carrying only the
 * byte-bounded World Graph JSON, the run goal, and the remaining step cap. `$0` / `--no-llm` rounds
 * (no tactical profile) make zero provider calls and convert World Graph observations into bounded
 * typed step proposals. Malformed output or provider failure returns a structured `parseError`.
 */
import type { z } from 'zod'
import { plannerResponseSchema as dispatchPlannerResponseSchema, stripJsonFences } from './exec-dispatch.ts'
import { isProfileHealthy, resolveProfilePoolForRole, type ResolvedModelProfile } from './model-settings.ts'
import { providerOptionsFor } from './provider-runtime-policy.ts'
import { providerPool, type UsageCallback } from './provider.ts'
import { serializeWorldGraph, type WorldGraphCausalEdge, type WorldGraphEndpointGroup, type WorldGraphFact, type WorldGraphSnapshot } from './world-graph.ts'

const DEFAULT_MAX_NEW_STEPS = 8
const SNAPSHOT_BYTE_BUDGET = 4096
const PLANNER_MAX_PROVIDER_CALLS = 2
const RAW_PREVIEW_CHARS = 160

/** Single authoritative planner response contract (shared with `applyPlannerNewSteps`). */
export const plannerResponseSchema = dispatchPlannerResponseSchema

export type LlmPlannerResponse = z.output<typeof plannerResponseSchema>
export type LlmPlannerStepProposal = LlmPlannerResponse['newSteps'][number]

export interface LlmPlannerParseError {
  stage: 'json' | 'schema' | 'provider'
  message: string
}

export interface LlmPlannerDecision {
  mode: 'llm' | 'deterministic-fallback'
  usedFallback: boolean
  providerCalls: number
  summary: string
  newSteps: LlmPlannerStepProposal[]
  cancelStepIds: string[]
  done: boolean
  parseError: LlmPlannerParseError | null
  droppedSteps: number
  snapshotBytes: number
  rawLength: number
  rawPreview: string
}

export interface PlanWithWorldGraphInput {
  runId: string
  goal: string
  roundNo: number
  snapshot: WorldGraphSnapshot
  /** Pre-serialized `<= 4 KB` snapshot; serialized from `snapshot` when omitted. */
  snapshotJson?: string
  approvedOrigins: readonly string[]
  profiles: readonly ResolvedModelProfile[]
  remainingStepCap: number
  maxNewSteps?: number
  noLlm?: boolean
  signal?: AbortSignal
  onUsage?: UsageCallback
  onProfileSuccess?: (profileId: string) => void
  onProfileFailure?: (profileId: string, err: string, hard: boolean) => void
}

function clip(text: string, max: number): string {
  const flat = text.replace(/\s+/g, ' ').trim()
  return flat.length <= max ? flat : `${flat.slice(0, Math.max(0, max - 1)).trimEnd()}…`
}

function hostOf(origin: string): string {
  try {
    return new URL(origin).host
  } catch {
    return clip(origin, 60)
  }
}

function stepCap(input: Pick<PlanWithWorldGraphInput, 'remainingStepCap' | 'maxNewSteps'>): number {
  const cap = Math.min(input.remainingStepCap, input.maxNewSteps ?? DEFAULT_MAX_NEW_STEPS)
  return Number.isFinite(cap) ? Math.max(0, Math.floor(cap)) : 0
}

function matrixSummary(group: WorldGraphEndpointGroup): string {
  return Object.entries(group.authMatrix).slice(0, 4)
    .map(([principal, c]) => `${principal}: 2xx=${c['2xx']} 401=${c['401']} 403=${c['403']} other=${c.other}`).join('; ')
}

function groupProposal(group: WorldGraphEndpointGroup): LlmPlannerStepProposal {
  return {
    title: clip(`World-graph access boundary · ${hostOf(group.origin)} · ${group.prefix}`, 200),
    hypothesis: clip(`Observed per-principal status asymmetry on ${group.methods.join('/')} ${group.sampleTemplates.join(', ')} (${matrixSummary(group)}). ` +
      'Verify whether the access boundary holds for every approved principal with control-vs-variant replays; read-only first, reversible benign deltas only for mutating routes.', 1200),
    category: 'broken-access-control', priority: group.mutating ? 88 : 84, origins: [group.origin],
    skills: ['access-control-bola-bfla', 'false-positive-elimination'], dependsOnFactIds: [], dependsOnStepIds: [],
  }
}

function factCategory(fact: WorldGraphFact): string {
  if (fact.kind === 'auth' || fact.kind === 'object_ref') return 'broken-access-control'
  if (fact.kind === 'cors') return 'cors-client-side'
  return 'misconfig-exposure'
}

function factProposal(fact: WorldGraphFact): LlmPlannerStepProposal {
  return {
    title: clip(`World-graph lead follow-up · ${hostOf(fact.origin)} · ${fact.route ?? fact.kind}`, 200),
    hypothesis: clip(`Verify unconfirmed ${fact.kind} observation${fact.route ? ` on ${fact.route}` : ''}: ${fact.summary}. Confirm or refute with a benign host-verified differential.`, 1200),
    category: factCategory(fact), priority: 80, origins: [fact.origin],
    skills: ['false-positive-elimination'], dependsOnFactIds: [fact.id], dependsOnStepIds: [],
  }
}

function edgeProposal(edge: WorldGraphCausalEdge): LlmPlannerStepProposal {
  const resource = edge.resourceKey ? ` carrying ${edge.resourceKey}` : ''
  return {
    title: clip(`World-graph cross-origin chain · ${hostOf(edge.fromOrigin)} → ${hostOf(edge.toOrigin)} · ${edge.to}`, 200),
    hypothesis: clip(`Observed ${edge.hostVerified ? 'host-verified' : 'runtime'} causal edge ${edge.from} on ${edge.fromOrigin} -> ${edge.to} on ${edge.toOrigin}${resource}. ` +
      'Verify whether the consumer independently enforces authorization for producer-derived identifiers.', 1200),
    category: 'broken-access-control', priority: 84, origins: [...new Set([edge.toOrigin, edge.fromOrigin])],
    skills: ['cross-host-chaining', 'multihop-chains'], dependsOnFactIds: [], dependsOnStepIds: [],
  }
}

/**
 * `$0` / `--no-llm` floor: zero provider calls. Round-robins auth-asymmetric unconfirmed groups,
 * unconfirmed leads/facts, and observed cross-origin causal edges into bounded typed proposals.
 */
export function buildDeterministicFallbackPlan(input: {
  snapshot: WorldGraphSnapshot
  approvedOrigins: readonly string[]
  remainingStepCap: number
  maxNewSteps?: number
}): LlmPlannerStepProposal[] {
  const cap = stepCap(input)
  const approved = new Set(input.approvedOrigins)
  const lanes: LlmPlannerStepProposal[][] = [
    input.snapshot.groups.filter(g => g.authAsymmetric && !g.confirmed).map(groupProposal),
    input.snapshot.facts.filter(f => !f.confirmed && (f.lead || f.route)).map(factProposal),
    input.snapshot.edges.filter(e => e.crossOrigin).map(edgeProposal),
  ]
  const out: LlmPlannerStepProposal[] = []
  const titles = new Set<string>()
  for (let i = 0; out.length < cap && lanes.some(lane => i < lane.length); i += 1) {
    for (const lane of lanes) {
      const proposal = lane[i]
      if (!proposal || out.length >= cap) continue
      const origins = proposal.origins.filter(origin => approved.size === 0 || approved.has(origin))
      const key = proposal.title.toLowerCase()
      if (!origins.length || titles.has(key)) continue
      titles.add(key)
      out.push({ ...proposal, origins })
    }
  }
  return out
}

function plannerMessages(input: PlanWithWorldGraphInput, snapshotJson: string, cap: number): { systemPrompt: string; user: string } {
  const systemPrompt = [
    'You are the chain planner for Kovo, a defensive web-application QA and security verification scanner running an authorized assessment.',
    'You receive a bounded pure-fact World Graph of already-observed run state: endpoint groups with per-principal status matrices, causal edges, facts/leads, and controller routes.',
    'Propose verification steps that target observed, unconfirmed surfaces (auth-asymmetric or mutating groups, unconfirmed leads, cross-origin edges).',
    'Describe hypotheses by verification class and route template only; never include exploit payloads, raw probe strings, or credentials.',
    'Respond with ONLY one JSON object, no prose.',
  ].join('\n')
  const header = JSON.stringify({
    task: 'world-graph single-turn planner round',
    goal: clip(input.goal, 400),
    roundNo: input.roundNo,
    remainingStepCap: cap,
    approvedOrigins: input.approvedOrigins.slice(0, 16),
    responseContract: {
      summary: 'string',
      newSteps: `array (<= ${cap}) of {title, hypothesis, category, priority 0-100, origins (subset of approvedOrigins), skills, dependsOnFactIds (World Graph fact ids), dependsOnStepIds}`,
      cancelStepIds: 'array of step ids (usually empty)',
      done: 'boolean: true only when no observed unconfirmed surface remains worth verifying',
    },
  })
  return { systemPrompt, user: `${header}\nWORLD_GRAPH=${snapshotJson}` }
}

async function streamPlannerAnswer(input: PlanWithWorldGraphInput, pool: ResolvedModelProfile[], prompt: { systemPrompt: string; user: string }): Promise<string> {
  const primary = pool.find(p => isProfileHealthy(p, Date.now())) ?? pool[0]
  const { models, model } = providerPool(pool, 'chain-planner', providerOptionsFor(input.runId, 'tactical', 'worker', {
    profile: primary, signal: input.signal, onUsage: input.onUsage, maxCalls: PLANNER_MAX_PROVIDER_CALLS,
    onProfileSuccess: input.onProfileSuccess, onProfileFailure: input.onProfileFailure,
  }))
  const stream = models.stream(model, {
    systemPrompt: prompt.systemPrompt,
    messages: [{ role: 'user', content: prompt.user, timestamp: Date.now() }],
    tools: [],
  })
  let out = ''
  for await (const ev of stream) {
    if (ev.type === 'text_delta' && typeof ev.delta === 'string') out += ev.delta
  }
  const res = await stream.result()
  if (res.stopReason === 'error' || res.stopReason === 'aborted') {
    throw new Error(clip(res.errorMessage ?? `planner stream ${res.stopReason}`, 240))
  }
  if (!out && Array.isArray(res.content)) {
    out = res.content
      .filter((p): p is { type: 'text'; text: string } => p.type === 'text' && typeof p.text === 'string')
      .map(p => p.text).join('')
  }
  return out.trim()
}

/** Parse a planner answer (fenced or bare JSON) into the shared contract with a typed parse error. */
function parsePlannerAnswer(answer: string): { data: LlmPlannerResponse | null; parseError: LlmPlannerParseError | null } {
  let json: unknown
  try {
    json = JSON.parse(stripJsonFences(answer))
  } catch (error) {
    return { data: null, parseError: { stage: 'json', message: clip(error instanceof Error ? error.message : String(error), 240) } }
  }
  const parsed = plannerResponseSchema.safeParse(json)
  if (!parsed.success) {
    const message = parsed.error.issues.slice(0, 4).map(i => `${i.path.join('.') || '<root>'}: ${i.message}`).join('; ')
    return { data: null, parseError: { stage: 'schema', message: clip(message, 240) } }
  }
  return { data: parsed.data, parseError: null }
}

/**
 * Turn one raw planner answer into a typed decision (shared by the World Graph turn and the gated
 * legacy tool planner). Proposals beyond `cap` are reported via `droppedSteps`; origin scoping,
 * dedupe and budget attribution stay in `applyPlannerNewSteps` so funnel accounting stays exact.
 */
export function decidePlannerAnswer(answer: string, cap: number, snapshotBytes = 0): LlmPlannerDecision {
  const { data, parseError } = parsePlannerAnswer(answer)
  const newSteps = data ? data.newSteps.slice(0, Math.max(0, cap)) : []
  return {
    mode: 'llm', usedFallback: false, providerCalls: 1, summary: data ? clip(data.summary, 300) : '', newSteps,
    cancelStepIds: data?.cancelStepIds ?? [], done: data?.done ?? false, parseError,
    droppedSteps: data ? data.newSteps.length - newSteps.length : 0, snapshotBytes,
    rawLength: answer.length, rawPreview: clip(answer, RAW_PREVIEW_CHARS),
  }
}

/** Closed-loop single-turn planner: deterministic `$0` floor or one bounded LLM call. Never throws. */
export async function planWithWorldGraph(input: PlanWithWorldGraphInput): Promise<LlmPlannerDecision> {
  const cap = stepCap(input)
  const snapshotJson = input.snapshotJson ?? serializeWorldGraph(input.snapshot, SNAPSHOT_BYTE_BUDGET)
  const base = { cancelStepIds: [] as string[], done: false, parseError: null, droppedSteps: 0, snapshotBytes: Buffer.byteLength(snapshotJson, 'utf8'), rawLength: 0, rawPreview: '' }
  const pool = input.noLlm ? [] : resolveProfilePoolForRole('tactical', input.profiles)
  if (pool.length === 0) {
    const newSteps = buildDeterministicFallbackPlan({ ...input, remainingStepCap: cap })
    return { ...base, mode: 'deterministic-fallback', usedFallback: true, providerCalls: 0, summary: `deterministic world-graph floor: ${newSteps.length} proposal(s)`, newSteps }
  }
  let answer = ''
  try {
    answer = await streamPlannerAnswer(input, pool, plannerMessages(input, snapshotJson, cap))
  } catch (error) {
    const message = clip(error instanceof Error ? error.message : String(error), 240)
    return { ...base, mode: 'llm', usedFallback: false, providerCalls: 1, summary: '', newSteps: [], parseError: { stage: 'provider', message } }
  }
  return decidePlannerAnswer(answer, cap, base.snapshotBytes)
}
