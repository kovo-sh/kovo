/**
 * Replay-spec synthesis: turns a probe signal into declarative specs for the Zero-LLM
 * `ReplayVerifier`. Specs are built only from what the probe observed (endpoint, param,
 * location, anomaly details), never from benchmark manifests. Per-kind builders live in
 * `benchmark-specs-{sql,http,proto}.ts`.
 */
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'
import { synthAuthz, synthCommandInjection, synthMassAssignment, synthSsrf, synthSsti, synthTraversal, synthXxe } from './benchmark-specs-http.ts'
import { synthM3Contracts } from './benchmark-specs-m3.ts'
import { synthAuthProtocol, synthCache } from './benchmark-specs-proto.ts'
import { synthNosql } from './benchmark-specs-nosql.ts'
import { synthSqlBoolean, synthSqlTime } from './benchmark-specs-sql.ts'
import { synthDomXss, synthGraphql, synthRace, synthReflectedXss, synthSecondOrderXss, synthUrlDomXss, synthWorkflow, synthWorkflowRepeatAccepted, synthWorkflowStepSkip } from './benchmark-specs-web.ts'
import type { SynthesizedSpec } from './benchmark-specs-common.ts'

export type { SynthesizedSpec } from './benchmark-specs-common.ts'

function build(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  // v5 M3 anomaly contracts (awaiting their probe shapes) are anomaly-gated and independent of class.
  const m3 = synthM3Contracts(o, env)
  if (m3.length > 0) return m3
  if (process.env.GUARDIAN_BENCH_DEBUG === '1') {
    const keys = o.hyp.probeClass === 'workflow_invariant'
      ? `qty=${o.hyp.quantityField ?? '-'} create=${o.hyp.createPath ?? '-'} read=${o.hyp.workflowReadPath ?? '-'} repeat=${o.hyp.repeatMutation === true} price=${o.hyp.priceTrust === true}`
      : `param=${o.hyp.param?.name ?? '-'}@${o.hyp.location ?? '-'}`
    process.stderr.write(`[spec-signal] ${o.hyp.probeClass} ${o.hyp.method} ${o.hyp.endpoint.path} types=${o.anomalies.map(a => String(a.type)).join(',') || 'none'} ${keys}\n`)
  }
  switch (o.hyp.probeClass) {
    case 'sqli_boolean': return synthSqlBoolean(o, env)
    case 'sqli_time_diff': return synthSqlTime(o, env)
    case 'nosqli_type': return synthNosql(o, env)
    case 'authz_matrix': return synthAuthz(o, env)
    case 'mass_assignment': return synthMassAssignment(o, env)
    case 'ssrf_canary': return synthSsrf(o, env)
    case 'xxe_canary': return synthXxe(o, env)
    case 'ssti_math': return synthSsti(o, env)
    case 'auth_protocol_audit': return synthAuthProtocol(o, env)
    case 'cache_poison_deception': return synthCache(o, env)
    case 'graphql_audit': return synthGraphql(o, env)
    case 'workflow_invariant': return [...synthWorkflow(o, env), ...synthWorkflowStepSkip(o, env), ...synthWorkflowRepeatAccepted(o, env)]
    case 'xss_context': return [...synthSecondOrderXss(o, env), ...synthUrlDomXss(o, env), ...synthDomXss(o, env), ...synthReflectedXss(o, env)]
    case 'path_traversal_benign': return synthTraversal(o, env)
    case 'command_injection': return synthCommandInjection(o, env)
    case 'race_burst': return synthRace(o, env)
    default: return []
  }
}

/** All schema-valid candidate specs for a signal, most specific first (callers stop at the first confirmed). */
export function synthesizeSpecs(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  if (o.verdict !== 'signal') return []
  let built: SynthesizedSpec[]
  try {
    built = build(o, env)
  } catch (err) {
    if (process.env.GUARDIAN_BENCH_DEBUG === '1') process.stderr.write(`[spec-error] ${o.hyp.probeClass} ${o.hyp.endpoint.path}: ${err instanceof Error ? err.message.slice(0, 200) : String(err).slice(0, 200)}\n`)
    return []
  }
  const out: SynthesizedSpec[] = []
  for (const candidate of built) {
    try {
      const parsed = declarativeReplaySpecSchema.safeParse(candidate.spec)
      if (parsed.success) out.push({ kind: candidate.kind, spec: parsed.data as unknown as Record<string, unknown> })
      else if (process.env.GUARDIAN_BENCH_DEBUG === '1') process.stderr.write(`[spec-invalid] ${o.hyp.probeClass} ${o.hyp.endpoint.path}: ${parsed.error.issues[0]?.path.join('.')} ${parsed.error.issues[0]?.message}\n`)
    } catch (err) {
      if (process.env.GUARDIAN_BENCH_DEBUG === '1') process.stderr.write(`[spec-invalid] ${o.hyp.probeClass} ${o.hyp.endpoint.path}: ${err instanceof Error ? err.message.slice(0, 160) : 'schema validation failed'}\n`)
    }
  }
  return out
}

export function synthesizeSpec(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  return synthesizeSpecs(o, env)[0] ?? null
}
