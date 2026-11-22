/** sql_boolean_diff / sql_time_diff spec synthesis from sqli probe signals. */
import { baseFields, stepOf } from './benchmark-specs-common.ts'
import type { SynthesizedSpec } from './benchmark-specs-common.ts'
import { probePathFor } from './benchmark-probes.ts'
import type { HypothesisOutcome, ProbeEnv } from './benchmark-probes.ts'

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

function injectionFields(o: HypothesisOutcome, env: ProbeEnv) {
  const param = o.hyp.param!
  const body: Record<string, unknown> = {}
  for (const p of o.hyp.endpoint.params) {
    if (p.name !== param.name && p.location === o.hyp.location && !p.isCsrf) body[p.name] = 'guardian'
  }
  const loc = o.hyp.location!
  return {
    targetOrigin: env.origin,
    method: o.hyp.method,
    pathAndQuery: probePathFor(o.hyp),
    ...(env.owner ? { persona: env.owner } : {}),
    ...(env.caps.sessionAndCsrf ? { session: env.session } : {}),
    ...(env.caps.sessionAndCsrf && o.hyp.endpoint.params.some(p => p.isCsrf) ? { csrfBind: true } : {}),
    ...(loc === 'json' || loc === 'form' ? { jsonBody: body } : {}),
    ...(loc === 'graphql_var' ? { jsonBody: { variables: body }, ...(o.ctx?.graphqlQuery ? { graphqlQuery: o.ctx.graphqlQuery } : {}) } : {}),
    ...(loc === 'xml' && o.ctx?.xmlTemplate ? { xmlTemplate: o.ctx.xmlTemplate } : {}),
    paramName: param.name,
    paramLocation: loc,
    baselineValue: o.ctx?.baseline ?? '1',
  }
}

/** A setup request that lets the broker jar learn session cookies and CSRF tokens before the rounds. */
function primingFields(env: ProbeEnv) {
  return env.caps.sessionAndCsrf
    ? { controlStep: stepOf(env, 'c0', 'setup', 'Load the entry page to bind session and CSRF cookies', { method: 'GET', pathAndQuery: '/' }, env.owner) }
    : {}
}

const jqBoolean = '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "boolean differential holds" }'
const jqTime = '{ controlPassed: (.sqlTimeDiff.controlPassed == true), confirmed: (.sqlTimeDiff.passed == true), observed: ("deltaMs=" + (.sqlTimeDiff.deltaMedianMs | tostring)), expected: "time differential holds" }'

const fallbackStyles = ['single_quote', 'numeric', 'double_quote', 'or_branch']

export function synthSqlBoolean(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  if (!o.hyp.param || !o.hyp.location) return []
  const hit = o.anomalies.find(a => a.type === 'boolean_differential')
  if (hit) {
    const s = booleanStyle(String(hit.style ?? 'single_quote'))
    return [{
      kind: 'sql_boolean_diff',
      spec: {
        ...baseFields(env, 'Boolean-based SQL injection differential', 'CWE-89', 'injection-input', 'high', jqBoolean),
        kind: 'sql_boolean_diff',
        ...injectionFields(o, env),
        ...primingFields(env),
        quoteStyle: s.quoteStyle,
        ...(s.valueTemplate ? { valueTemplate: s.valueTemplate } : {}),
      },
    }]
  }
  const hasErrorSignal = o.anomalies.some(a => a.type === 'db_error_fingerprint')
  if (!hasErrorSignal) return []
  if (o.hyp.location === 'graphql_var') return []
  // Error fingerprint proves the value reaches a SQL string literal. A tautology baseline plus the
  // verifier's randomized `k=k` / `k=k+1` triplet still yields a genuine boolean differential.
  const out: SynthesizedSpec[] = [{
    kind: 'sql_boolean_diff',
    spec: {
      ...baseFields(env, 'SQL injection via string-literal breakout (error fingerprint)', 'CWE-89', 'injection-input', 'high', jqBoolean),
      kind: 'sql_boolean_diff',
      ...injectionFields(o, env),
      ...primingFields(env),
      baselineValue: "x' OR 1=1-- -",
      quoteStyle: 'single',
      valueTemplate: "x' OR {{sql_expr}}-- -",
    },
  }]
  // Additional observed-shape candidates, tried only when the generic breakout does not confirm.
  for (const style of fallbackStyles) {
    const s = booleanStyle(style)
    out.push({
      kind: 'sql_boolean_diff',
      spec: {
        ...baseFields(env, 'Boolean-based SQL injection differential', 'CWE-89', 'injection-input', 'high', jqBoolean),
        kind: 'sql_boolean_diff',
        ...injectionFields(o, env),
        ...primingFields(env),
        quoteStyle: s.quoteStyle,
        ...(s.valueTemplate ? { valueTemplate: s.valueTemplate } : {}),
      },
    })
  }
  return out
}

export function synthSqlTime(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'sql_time_differential')
  if (!hit || !o.hyp.param || !o.hyp.location) return []
  // The typed time-diff schema only supports query/path/json/form injection.
  if (o.hyp.location === 'xml' || o.hyp.location === 'graphql_var' || o.hyp.location === 'header') return []
  const style = String(hit.style ?? 'single_quote')
  const dialectRaw = String(hit.dialect ?? '')
  if (!['postgres', 'mysql', 'sqlite', 'mssql'].includes(dialectRaw)) return []
  const dialect = dialectRaw as 'postgres' | 'mysql' | 'sqlite' | 'mssql'
  const delay = Math.max(1500, Math.min(3000, Number(hit.delayMs) || 1500))
  return [{
    kind: 'sql_time_diff',
    spec: {
      ...baseFields(env, 'Time-based blind SQL injection differential', 'CWE-89', 'injection-input', 'high', jqTime),
      kind: 'sql_time_diff',
      ...injectionFields(o, env),
      ...primingFields(env),
      quoteStyle: booleanStyle(style).quoteStyle,
      dialect,
      delayMs: Math.round(delay),
    },
  }]
}
