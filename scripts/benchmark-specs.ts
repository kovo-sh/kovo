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
import { synthNosql } from './benchmark-specs-nosql.ts'
import { synthRaceBurst } from './benchmark-specs-race.ts'
import { synthRce } from './benchmark-specs-rce.ts'
import { synthSqlBoolean, synthSqlTime } from './benchmark-specs-sql.ts'
import { synthDomXss, synthGraphql, synthReflectedXss, synthSecondOrderXss, synthWorkflow } from './benchmark-specs-web.ts'
import type { SynthesizedSpec } from './benchmark-specs-common.ts'

export type { SynthesizedSpec } from './benchmark-specs-common.ts'

function build(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  // Race evidence can arrive on any probe class as the probes stream grows; it is schema-distinct.
  const race = synthRaceBurst(o, env)
  if (race.length > 0) return race
  switch (o.hyp.probeClass) {
    case 'sqli_boolean': return synthSqlBoolean(o, env)
    case 'sqli_time_diff': return synthSqlTime(o, env)
    case 'nosqli_type': return synthNosql(o, env)
    case 'authz_matrix': return synthAuthz(o, env)
    case 'mass_assignment': return synthMassAssignment(o, env)
    case 'ssrf_canary': return synthSsrf(o, env)
    case 'xxe_canary': return synthXxe(o, env)
    // SSTI and shell-style execution share the rce_proof schema; each builder only fires on its own
    // observed evidence, and template evidence is offered first.
    case 'ssti_math': return [...synthSsti(o, env), ...synthRce(o, env)]
    case 'auth_protocol_audit': return synthAuthProtocol(o, env)
    case 'cache_poison_deception': return synthCache(o, env)
    case 'graphql_audit': return synthGraphql(o, env)
    case 'workflow_invariant': return synthWorkflow(o, env)
    case 'xss_context': return [...synthSecondOrderXss(o, env), ...synthDomXss(o, env), ...synthReflectedXss(o, env)]
    // Path normalization alone never proves a jail escape; a future read-oracle anomaly is required.
    case 'path_traversal_benign': return []
    default: return synthRce(o, env)
  }
}

/** Probe classes whose signals intentionally produce no spec yet, with the missing evidence. */
const SKIP_REASONS: Partial<Record<string, string>> = {
  path_traversal_benign: 'normalization-only evidence; needs an out-of-jail read oracle (escaped path + foreign content + nonexistent-sibling control)',
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
  if (out.length === 0 && process.env.GUARDIAN_BENCH_DEBUG === '1') {
    const reason = SKIP_REASONS[o.hyp.probeClass]
    if (reason) process.stderr.write(`[spec-skip] ${o.hyp.probeClass} ${o.hyp.endpoint.path}: ${reason}\n`)
  }
  return out
}

export function synthesizeSpec(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  return synthesizeSpecs(o, env)[0] ?? null
}
