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
/** Dialect-specific conditional-delay payload for a timing arm. */
function timingPayload(dialect: string | undefined, baseline: string, delayMs: number, delaySec: string): string {
  switch (dialect) {
    case 'mysql': return `${baseline}' AND SLEEP(${delaySec})-- -`
    case 'mssql': return `${baseline}'; WAITFOR DELAY '0:0:${Math.max(1, Math.round(delayMs / 1000))}'-- -`
    case 'sqlite': return `${baseline}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${delayMs * 25_000}))))-- -`
    default: return `${baseline}' AND (SELECT 1 FROM pg_sleep(${delaySec})) IS NULL-- -`
  }
}

/**
 * The receipt rule follows the evidence shape. A boolean sink separates rows/content; a
 * status-only sink answers 2xx for the benign/true arms and a 4xx for the false predicate (the
 * legacy VM's `false.status !== true.status && false.status < 500`). Choosing the wrong mode is
 * how a status-only target ends up "no structural change".
 */
function booleanModeFor(o: HypothesisOutcome): 'boolean' | 'status' {
  const signals = Array.isArray(o.details.booleanSignals)
    ? o.details.booleanSignals as Array<{ passed?: boolean; rounds?: Array<Record<string, unknown>> }>
    : []
  const passed = signals.find(signal => signal.passed) ?? signals[0]
  const rounds = passed?.rounds ?? []
  if (rounds.length === 0) return 'boolean'
  const num = (value: unknown): number => (typeof value === 'number' ? value : -1)
  const statusOnly = rounds.every(round => {
    const base = num(round.statusBase)
    const truth = num(round.statusTrue)
    const falseArm = num(round.statusFalse)
    return base >= 200 && base < 300 && truth >= 200 && truth < 300 && falseArm >= 400 && falseArm < 500
  })
  return statusOnly ? 'status' : 'boolean'
}

function cut3RecipeEnvelope(
  o: HypothesisOutcome,
  env: ProbeEnv,
  mode: 'boolean' | 'status' | 'timing',
  selection: {
    baselineValue: string
    quoteStyle?: string
    valueTemplate?: string
    payload?: string
    contradiction?: string
    delayMs?: number
    dialect?: string
  },
): { recipeId: 'boolean_or_timing'; args: Record<string, unknown> } | undefined {
  const fields = injectionFields(o, env)
  const location = fields.paramLocation
  if (!['query', 'json', 'form', 'header', 'path', 'xml', 'graphql_var'].includes(location)) return undefined
  const armFor = (value: string): {
    pathAndQuery: string
    jsonBody?: unknown
    textBody?: string
    headers?: Record<string, string>
  } => {
    if (location === 'query') {
      try {
        const url = new URL(fields.pathAndQuery, 'http://guardian.invalid')
        url.searchParams.set(fields.paramName, value)
        return { pathAndQuery: `${url.pathname}${url.search}` }
      } catch {
        return { pathAndQuery: fields.pathAndQuery }
      }
    }
    if (location === 'header') {
      return { pathAndQuery: fields.pathAndQuery, headers: { [fields.paramName]: value } }
    }
    if (location === 'path') {
      const [basePath, query] = fields.pathAndQuery.split('?', 2)
      const segments = (basePath ?? '/').split('/')
      const last = segments.length - 1
      if (last > 0) segments[last] = encodeURIComponent(value)
      return { pathAndQuery: `${segments.join('/')}${query ? `?${query}` : ''}` }
    }
    if (location === 'form') {
      // The route parses `application/x-www-form-urlencoded`; a JSON body would make the parameter
      // invisible and both arms identical.
      const base = ((fields.jsonBody as Record<string, unknown> | undefined) ?? {})
      const params = new URLSearchParams()
      for (const [name, raw] of Object.entries(base)) {
        if (name === fields.paramName) continue
        params.set(name, String(raw))
      }
      params.set(fields.paramName, value)
      return {
        pathAndQuery: fields.pathAndQuery,
        textBody: params.toString(),
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
      }
    }
    if (location === 'xml') {
      const template = String((fields as { xmlTemplate?: string }).xmlTemplate ?? '')
      const escapeXml = (input: string): string => input
        .replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;')
      const tag = fields.paramName.replace(/[^A-Za-z0-9_.-]/g, '') || 'value'
      const generic = `<?xml version="1.0"?><request><${tag}>${escapeXml(value)}</${tag}></request>`
      const baseline = String(selection.baselineValue)
      let textBody: string
      if (template.includes('{{val}}') || template.includes(`{{${fields.paramName}}}`)) {
        textBody = template
          .split('{{val}}').join(value)
          .split(`{{${fields.paramName}}}`).join(value)
      } else if (baseline && template.includes(baseline)) {
        textBody = template.split(baseline).join(value)
      } else {
        // No placeholder and no literal baseline: replace the contents of the element named after
        // the declared parameter; fall back to a minimal document when the template lacks it.
        const replaced = template.replace(
          new RegExp(`(<${tag}\\b[^>]*>)([\\s\\S]*?)(</${tag}>)`, 'i'),
          (_match, open: string, _inner: string, close: string) => `${open}${escapeXml(value)}${close}`,
        )
        textBody = replaced !== template ? replaced : generic
      }
      return {
        pathAndQuery: fields.pathAndQuery,
        textBody,
        headers: { 'Content-Type': 'application/xml' },
      }
    }
    if (location === 'graphql_var') {
      const variables = { ...((fields.jsonBody as { variables?: Record<string, unknown> } | undefined)?.variables ?? {}) }
      variables[fields.paramName] = value
      return {
        pathAndQuery: fields.pathAndQuery,
        jsonBody: { ...(o.ctx?.graphqlQuery ? { query: o.ctx.graphqlQuery } : {}), variables },
      }
    }
    return {
      pathAndQuery: fields.pathAndQuery,
      jsonBody: { ...((fields.jsonBody as Record<string, unknown> | undefined) ?? {}), [fields.paramName]: value },
    }
  }
  const baseline = selection.baselineValue
  const delayMs = Math.max(1500, Math.min(3000, Math.round(selection.delayMs ?? 2500)))
  const delaySec = (delayMs / 1000).toFixed(2)
  const fillDelay = (value: string): string => value
    .replaceAll('{{baseline}}', baseline)
    .replaceAll('{{delay_sec}}', delaySec)
    .replaceAll('{{delay_ms}}', String(delayMs))
  let trueValue: string
  if (selection.valueTemplate) {
    trueValue = fillDelay(selection.valueTemplate).replaceAll('{{sql_expr}}', '1=1')
  } else if (mode === 'timing') {
    trueValue = timingPayload(selection.dialect, baseline, delayMs, delaySec)
  } else if (selection.payload) {
    trueValue = selection.payload
  } else {
    trueValue = `${baseline}' AND 1=1-- -`
  }
  const falseValue = selection.contradiction ?? `${baseline}' AND 1=2-- -`
  // The receipt `boolean` rule compares a TRUE predicate against a FALSE predicate (the legacy VM
  // used the randomized `k=k` / `k=k+1` pair). A benign-baseline-vs-true pair is identical by
  // construction and could never confirm, so the control arm is the true predicate.
  const control = armFor(mode === 'boolean' ? trueValue : baseline)
  const probe = armFor(mode === 'boolean' ? falseValue : trueValue)
  const contradiction = armFor(falseValue)
  // A path/header/xml parameter cannot be moved by a query or JSON arm builder.
  if (!probe.pathAndQuery && !probe.jsonBody) return undefined
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
    // CSRF material only belongs on a form carrier: binding a token into an XML/JSON/header/path
    // arm would rewrite the payload and make both arms identical.
    ...(env.caps.sessionAndCsrf && location === 'form'
      ? { session: env.session, csrfBind: true, primePath: '/' }
      : {}),
  }
  const args = mode === 'timing'
    ? {
        ...baseArgs,
        receiptClass: 'blind_sqli',
        controlPathAndQuery: control.pathAndQuery,
        probePathAndQuery: probe.pathAndQuery,
        controlRequest: control,
        probeRequest: probe,
        ...(control.jsonBody ? { controlJsonBody: control.jsonBody } : {}),
        ...(probe.jsonBody ? { probeJsonBody: probe.jsonBody } : {}),
      }
    : mode === 'status'
      ? {
          ...baseArgs,
          receiptClass: 'sqli_status',
          rounds: 2,
          controlPathAndQuery: control.pathAndQuery,
          probePathAndQuery: probe.pathAndQuery,
          contradictionPathAndQuery: contradiction.pathAndQuery,
          controlRequest: control,
          probeRequest: probe,
          contradictionRequest: contradiction,
          ...(control.jsonBody ? { controlJsonBody: control.jsonBody } : {}),
          ...(probe.jsonBody ? { probeJsonBody: probe.jsonBody } : {}),
          ...(contradiction.jsonBody ? { contradictionJsonBody: contradiction.jsonBody } : {}),
        }
      : {
          ...baseArgs,
          rounds: 2,
          controlPathAndQuery: control.pathAndQuery,
          probePathAndQuery: probe.pathAndQuery,
          controlRequest: control,
          probeRequest: probe,
          ...(control.jsonBody ? { controlJsonBody: control.jsonBody } : {}),
          ...(probe.jsonBody ? { probeJsonBody: probe.jsonBody } : {}),
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
    const envelope = cut3RecipeEnvelope(o, env, booleanModeFor(o), {
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
    delayMs: Math.round(delay),
    dialect,
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
