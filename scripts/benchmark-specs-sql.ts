/** sql_boolean_diff / sql_time_diff spec synthesis from sqli probe signals. */
import { baseFields } from './benchmark-specs-common.ts'
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

const jqBoolean = '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "boolean differential holds" }'
const jqTime = '{ controlPassed: (.sqlTimeDiff.controlPassed == true), confirmed: (.sqlTimeDiff.passed == true), observed: ("deltaMs=" + (.sqlTimeDiff.deltaMedianMs | tostring)), expected: "time differential holds" }'

const fallbackStyles = ['single_quote', 'numeric', 'double_quote', 'or_branch']

export function synthSqlBoolean(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  if (!o.hyp.param || !o.hyp.location) return []
  const hit = o.anomalies.find(a => a.type === 'boolean_differential')
  const hasErrorSignal = o.anomalies.some(a => a.type === 'db_error_fingerprint')
  const styles = hit ? [String(hit.style ?? 'single_quote')] : hasErrorSignal ? fallbackStyles : []
  return styles.map(style => {
    const s = booleanStyle(style)
    return {
      kind: 'sql_boolean_diff',
      spec: {
        ...baseFields(env, 'Boolean-based SQL injection differential', 'CWE-89', 'injection-input', 'high', jqBoolean),
        kind: 'sql_boolean_diff',
        ...injectionFields(o, env),
        quoteStyle: s.quoteStyle,
        ...(s.valueTemplate ? { valueTemplate: s.valueTemplate } : {}),
      },
    }
  })
}

export function synthSqlTime(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  const hit = o.anomalies.find(a => a.type === 'sql_time_differential')
  if (!hit || !o.hyp.param || !o.hyp.location) return []
  const style = String(hit.style ?? 'single_quote')
  const dialect = ['postgres', 'mysql', 'sqlite', 'mssql'].includes(String(hit.dialect)) ? String(hit.dialect) : 'postgres'
  const delay = Math.max(1500, Math.min(3000, Number(hit.delayMs) || 1500))
  return [{
    kind: 'sql_time_diff',
    spec: {
      ...baseFields(env, 'Time-based blind SQL injection differential', 'CWE-89', 'injection-input', 'high', jqTime),
      kind: 'sql_time_diff',
      ...injectionFields(o, env),
      quoteStyle: booleanStyle(style).quoteStyle,
      dialect,
      delayMs: Math.round(delay),
    },
  }]
}
