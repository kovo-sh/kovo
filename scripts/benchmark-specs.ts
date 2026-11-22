/**
 * Replay-spec synthesis: turns a probe signal into declarative specs for the Zero-LLM
 * `ReplayVerifier`. Specs are built only from what the probe observed (endpoint, param,
 * location, anomaly details), never from benchmark manifests. Per-kind builders live in
 * `benchmark-specs-{sql,http,proto}.ts`.
 */
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'
import { synthAuthz, synthMassAssignment, synthSsrf, synthSsti, synthXxe } from './benchmark-specs-http.ts'
import { synthAuthProtocol, synthCache } from './benchmark-specs-proto.ts'
import { synthSqlBoolean, synthSqlTime } from './benchmark-specs-sql.ts'
import type { SynthesizedSpec } from './benchmark-specs-common.ts'

export type { SynthesizedSpec } from './benchmark-specs-common.ts'

function build(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  switch (o.hyp.probeClass) {
    case 'sqli_boolean': return synthSqlBoolean(o, env)
    case 'sqli_time_diff': return synthSqlTime(o, env)
    case 'authz_matrix': return synthAuthz(o, env)
    case 'mass_assignment': return synthMassAssignment(o, env)
    case 'ssrf_canary': return synthSsrf(o, env)
    case 'xxe_canary': return synthXxe(o, env)
    case 'ssti_math': return synthSsti(o, env)
    case 'auth_protocol_audit': return synthAuthProtocol(o, env)
    case 'cache_poison_deception': return synthCache(o, env)
    default: return []
  }
}

/** All schema-valid candidate specs for a signal, most specific first (callers stop at the first confirmed). */
export function synthesizeSpecs(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  if (o.verdict !== 'signal') return []
  const out: SynthesizedSpec[] = []
  for (const built of build(o, env)) {
    const parsed = declarativeReplaySpecSchema.safeParse(built.spec)
    if (parsed.success) out.push({ kind: built.kind, spec: parsed.data as unknown as Record<string, unknown> })
    else if (process.env.GUARDIAN_BENCH_DEBUG === '1') process.stderr.write(`[spec-invalid] ${o.hyp.probeClass} ${o.hyp.endpoint.path}: ${parsed.error.issues[0]?.path.join('.')} ${parsed.error.issues[0]?.message}\n`)
  }
  return out
}

export function synthesizeSpec(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  return synthesizeSpecs(o, env)[0] ?? null
}
