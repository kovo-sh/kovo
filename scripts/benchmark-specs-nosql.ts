/**
 * NoSQL operator-injection / type-confusion spec synthesis.
 *
 * The probe's `operator_type_divergence` anomaly is only accepted when a neutral object control
 * matched the baseline (so a generic "object instead of string" error is not enough) and the
 * operator-typed value still produced a successful, different response.
 */
import { baseFields, is2xx, requestPartsForValue, sameAsControl, stepOf } from './benchmark-specs-common.ts'
import type { SynthesizedSpec } from './benchmark-specs-common.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

const OPERATORS: Record<string, (marker: string) => Record<string, unknown>> = {
  ne: marker => ({ $ne: marker }),
  gt_empty: () => ({ $gt: '' }),
}

export function synthNosql(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'operator_type_divergence')
  if (!hit) return []
  const operator = String(hit.operator ?? '')
  const build = OPERATORS[operator]
  if (!build) return []
  const status = Number(hit.status)
  if (!(status >= 200 && status < 500)) return []
  // Neutral object control must have matched the primitive baseline; otherwise the divergence is
  // just request-shape rejection rather than query-operator interpretation.
  if (o.details.neutralMatchesBase !== true) return []
  const marker = 'kovo'
  const baseline = requestPartsForValue(o, env, marker)
  const neutral = requestPartsForValue(o, env, { gx: marker })
  const probe = requestPartsForValue(o, env, build(marker))
  if (!baseline || !neutral || !probe) return []
  const jq = `{ controlPassed: ((${is2xx('c1')}) and (${is2xx('c2')}) and (${sameAsControl('c2', 'c1')})), ` +
    `confirmed: ((${is2xx('p1')}) and (.steps.p1.body != .steps.c2.body) and ((.steps.p1.body | length) > 2)), ` +
    'observed: ("probe bytes=" + (.steps.p1.body | length | tostring)), expected: "operator-typed values are not interpreted as query operators" }'
  return [{
    kind: 'http_chain',
    spec: {
      ...baseFields(env, 'NoSQL operator injection (type confusion)', 'CWE-943', 'injection-input', 'high', jq),
      kind: 'http_chain',
      steps: [
        stepOf(env, 'c1', 'control', 'Primitive string baseline', baseline),
        stepOf(env, 'c2', 'control', 'Neutral object that must behave like the baseline', neutral),
        stepOf(env, 'p1', 'probe', `Query-operator object (${operator}) changes the result set`, probe),
      ],
    },
  }]
}
