/**
 * Replay-spec synthesis: turns a probe signal into a declarative spec for the Zero-LLM
 * `ReplayVerifier`. Specs are built only from what the probe observed (endpoint, param,
 * location, anomaly details), never from benchmark manifests.
 */
import { declarativeReplaySpecSchema } from '../src/replay-spec.ts'
import { fillPlaceholders, hasPathPlaceholder, probePathFor } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

export interface SynthesizedSpec {
  kind: string
  spec: Record<string, unknown>
}

function baseFields(env: ProbeEnv, title: string, cwe: string, category: string, severity: 'high' | 'critical' | 'medium', jq: string) {
  return {
    version: 1,
    origin: env.origin,
    title,
    category,
    cwe,
    severity,
    severityRationale: 'Deterministic differential evidence was reproduced by the Zero-LLM verifier.',
    impact: 'An attacker can read or alter data outside their authorization.',
    remediation: 'Validate and parameterize input; enforce server-side ownership checks.',
    recheckInstructions: 'Replay the control and probe requests and compare the responses.',
    assertionsJq: jq,
  }
}

const jqStr = (v: string) => JSON.stringify(v)

function booleanStyle(style: string): { quoteStyle: 'single' | 'double' | 'numeric'; valueTemplate?: string } {
  switch (style) {
    case 'numeric': return { quoteStyle: 'numeric' }
    case 'double_quote': return { quoteStyle: 'double' }
    case 'single_quote': return { quoteStyle: 'single' }
    case 'or_branch': return { quoteStyle: 'single', valueTemplate: "{{baseline}}' OR {{sql_expr}}-- -" }
    case 'single_paren': return { quoteStyle: 'single', valueTemplate: "{{baseline}}') AND {{sql_expr}}-- -" }
    case 'single_double_paren': return { quoteStyle: 'single', valueTemplate: "{{baseline}}')) AND {{sql_expr}}-- -" }
    case 'like_breakout': return { quoteStyle: 'single', valueTemplate: "{{baseline}}%' AND {{sql_expr}}-- -" }
    case 'order_by': return { quoteStyle: 'single', valueTemplate: '{{baseline}} ORDER BY (CASE WHEN ({{sql_expr}}) THEN 1 ELSE 2 END)-- -' }
    default: return { quoteStyle: 'single' }
  }
}

function synthBooleanSqli(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'boolean_differential')
  const param = o.hyp.param
  if (!hit || !param || !o.hyp.location) return null
  const style = booleanStyle(String(hit.style ?? 'single_quote'))
  const body: Record<string, unknown> = {}
  for (const p of o.hyp.endpoint.params) {
    if (p.name !== param.name && p.location === o.hyp.location && !p.isCsrf) body[p.name] = 'guardian'
  }
  const spec = {
    ...baseFields(env, 'Boolean-based SQL injection differential', 'CWE-89', 'injection-input', 'high',
      '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "boolean differential holds" }'),
    kind: 'sql_boolean_diff',
    targetOrigin: env.origin,
    method: o.hyp.method,
    pathAndQuery: probePathFor(o.hyp),
    ...(env.owner ? { persona: env.owner } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    ...(env.caps.sessionAndCsrf && o.hyp.endpoint.params.some(p => p.isCsrf) ? { csrfBind: true } : {}),
    ...(o.hyp.location === 'json' || o.hyp.location === 'form' ? { jsonBody: body } : {}),
    paramName: param.name,
    paramLocation: o.hyp.location,
    baselineValue: '1',
    quoteStyle: style.quoteStyle,
    ...(style.valueTemplate ? { valueTemplate: style.valueTemplate } : {}),
  }
  return { kind: 'sql_boolean_diff', spec }
}

function synthAuthz(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  const hit = o.anomalies.find(a => a.type === 'unauthorized_access' && a.actor === 'other_persona')
  if (!hit || !env.owner || !env.other) return null
  const id = String(hit.resourceId)
  const method = String(hit.method ?? 'GET')
  const path = hasPathPlaceholder(o.hyp.endpoint.path)
    ? fillPlaceholders(o.hyp.endpoint.path, encodeURIComponent(id))
    : `${o.hyp.endpoint.path}?${o.hyp.endpoint.params.find(p => p.location === 'query')?.name ?? 'id'}=${encodeURIComponent(id)}`
  const request = (persona: string) => ({
    origin: env.origin, method, pathAndQuery: path, persona,
    followRedirects: false,
    ...(method !== 'GET' ? { jsonBody: {} } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
  })
  const jq = '{ controlPassed: (.steps.c1.status >= 200 and .steps.c1.status < 300), ' +
    'confirmed: (.steps.p1.status >= 200 and .steps.p1.status < 300 and ((.steps.p1.body == .steps.c1.body) or (((.steps.p1.json | keys?) // []) == ((.steps.c1.json | keys?) // []) and ((.steps.p1.body | length) > 2)))), ' +
    'observed: ("status=" + (.steps.p1.status | tostring)), expected: "non-owner denied" }'
  const spec = {
    ...baseFields(env, 'Cross-actor object access', 'CWE-639', 'broken-access-control', 'high', jq),
    kind: 'http_chain',
    steps: [
      { id: 'c1', role: 'control', description: 'Resource owner reads the object', request: request(env.owner) },
      { id: 'p1', role: 'probe', description: `Different actor reads the same object ${jqStr(id).slice(0, 40)}`, request: request(env.other) },
    ],
  }
  return { kind: 'http_chain', spec }
}

export function synthesizeSpec(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec | null {
  if (o.verdict !== 'signal') return null
  let built: SynthesizedSpec | null = null
  switch (o.hyp.probeClass) {
    case 'sqli_boolean': built = synthBooleanSqli(o, env); break
    case 'authz_matrix': built = synthAuthz(o, env); break
    default: built = null
  }
  if (!built) return null
  const parsed = declarativeReplaySpecSchema.safeParse(built.spec)
  return parsed.success ? { kind: built.kind, spec: parsed.data as unknown as Record<string, unknown> } : null
}
