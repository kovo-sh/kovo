// Probe family module — implementation moved verbatim from surface-engine.ts (no behavior change).
import { injectParam, randToken } from './context.ts'
import type { DiffContext, DiffOutcome } from './context.ts'
import type { ProbeModule } from './registry.ts'



export type ReflectionContext = 'event_handler_attr' | 'href_url' | 'js_string' | 'html_attr' | 'html_body'



export interface ReflectionAnalysis {
  reflected: boolean
  context: ReflectionContext
  unencodedChars: string[]
  domSinkHint: string | null
  mediaType: string
  renderable: boolean
  exploitable: boolean
  /** Number of canary occurrences inspected (bounded scan). */
  occurrences?: number
  /** Index of the occurrence the returned context/unencodedChars describe. */
  occurrenceIndex?: number
}

/** Suffix `diffXssContext` appends to the canary. Escaping is judged per character of this sequence. */
const CANARY_SUFFIX = `"'<>`
/** Bound the occurrence scan so a page that reflects the marker thousands of times stays cheap. */
const MAX_OCCURRENCES = 50

const NAMED_ENTITY: Record<string, string> = { quot: '"', apos: "'", lt: '<', gt: '>' }
const URL_ATTR = /^(?:href|src|action|formaction|poster|background|cite|longdesc|codebase|data|xlink:href)$/i

/**
 * Length of the encoding of `expected` at the start of `rest`, or 0 when `rest` does not encode it.
 * Covers HTML entities (named, decimal, hex), percent-encoding and JS string escapes.
 */
function encodedLength(rest: string, expected: string): number {
  const code = expected.codePointAt(0)!
  let m = /^&(quot|apos|lt|gt);?/i.exec(rest)
  if (m) return NAMED_ENTITY[m[1]!.toLowerCase()] === expected ? m[0].length : 0
  m = /^&#(?:x([0-9a-f]{1,6})|([0-9]{1,7}));?/i.exec(rest)
  if (m) {
    const decoded = m[1] !== undefined ? Number.parseInt(m[1], 16) : Number.parseInt(m[2]!, 10)
    return decoded === code ? m[0].length : 0
  }
  m = /^%(22|27|3c|3e)/i.exec(rest)
  if (m) return Number.parseInt(m[1]!, 16) === code ? 3 : 0
  m = /^\\u\{(22|27|3c|3e)\}/i.exec(rest)
  if (m) return Number.parseInt(m[1]!, 16) === code ? m[0].length : 0
  m = /^\\u(22|27|3c|3e)/i.exec(rest)
  if (m) return Number.parseInt(m[1]!, 16) === code ? m[0].length : 0
  m = /^\\x(22|27|3c|3e)/i.exec(rest)
  if (m) return Number.parseInt(m[1]!, 16) === code ? m[0].length : 0
  if (rest[0] === '\\' && rest[1] === expected) return 2
  return 0
}

/**
 * Parse the injected suffix immediately after a canary occurrence. Only characters that belong to
 * the injected sequence are considered: a `"` closing an unrelated attribute, or markup that
 * follows a stripped marker, is not part of the echo and must not count as unencoded.
 */
function analyzeSuffix(body: string, idx: number, canaryLength: number): { rawChars: string[]; encodedChars: string[]; matched: number } {
  const tail = body.slice(idx + canaryLength, idx + canaryLength + 48)
  const rawChars: string[] = []
  const encodedChars: string[] = []
  let cursor = 0
  for (const expected of CANARY_SUFFIX) {
    const enc = encodedLength(tail.slice(cursor), expected)
    if (enc > 0) { encodedChars.push(expected); cursor += enc; continue }
    if (tail[cursor] === expected) { rawChars.push(expected); cursor += 1; continue }
    break
  }
  return { rawChars, encodedChars, matched: rawChars.length + encodedChars.length }
}

/** True when the occurrence sits inside an HTML comment, where markup characters are inert. */
function insideComment(body: string, idx: number): boolean {
  const before = body.slice(Math.max(0, idx - 4000), idx).toLowerCase()
  const open = before.lastIndexOf('<!--')
  return open >= 0 && before.indexOf('-->', open) < 0
}

/** Reflect the attribute whose value currently contains the occurrence, if any. */
function attributeContext(tag: string): ReflectionContext | null {
  const attrRe = /([A-Za-z_:][-A-Za-z0-9_:.]*)\s*=\s*/g
  let last: { name: string; valueStart: number } | null = null
  let m: RegExpExecArray | null
  while ((m = attrRe.exec(tag)) !== null) last = { name: m[1]!.toLowerCase(), valueStart: m.index + m[0].length }
  if (!last) return null
  const quote = tag[last.valueStart]
  if ((quote === '"' || quote === "'") && tag.indexOf(quote, last.valueStart + 1) >= 0) {
    // The value closed before the occurrence; the marker is between attributes inside the tag.
    return 'html_attr'
  }
  if (/^on[a-z]+$/.test(last.name)) return 'event_handler_attr'
  if (URL_ATTR.test(last.name)) return 'href_url'
  return 'html_attr'
}

/** Classify the rendering context of a single occurrence. */
function classifyContext(body: string, idx: number): ReflectionContext {
  const before = body.slice(Math.max(0, idx - 500), idx)
  const lower = before.toLowerCase()
  const scriptOpen = lower.lastIndexOf('<script')
  if (scriptOpen >= 0 && lower.indexOf('</script>', scriptOpen) < 0) return 'js_string'
  if (before.lastIndexOf('<') > before.lastIndexOf('>')) return attributeContext(before.slice(before.lastIndexOf('<'))) ?? 'html_attr'
  return 'html_body'
}

/**
 * Exploitability of one occurrence. A dangerous character only matters when it is
 * (a) actually a raw payload character (not its entity/percent/JS-escape form) and
 * (b) meaningful for the context it sits in.
 */
function occurrenceExploitable(context: ReflectionContext, rawChars: string[], matched: number, domSinkHint: string | null): boolean {
  // A marker echoed without a recognizable injected suffix (sanitizer stripped it) or a single
  // ambiguous character next to unrelated markup is not evidence of an unencoded sink.
  if (matched < 2) return false
  const has = (c: string): boolean => rawChars.includes(c)
  switch (context) {
    case 'html_body': return has('<') || has('>') || (Boolean(domSinkHint) && rawChars.length > 0)
    case 'html_attr': return has('"') || has("'")
    case 'event_handler_attr': return has('"') || has("'") || has('<') || (Boolean(domSinkHint) && rawChars.length > 0)
    case 'js_string': return has('"') || has("'") || has('<') || (Boolean(domSinkHint) && rawChars.length > 0)
    case 'href_url': return has('"') || has("'")
  }
}

const CONTEXT_RANK: Record<ReflectionContext, number> = {
  html_body: 100, js_string: 90, event_handler_attr: 85, href_url: 70, html_attr: 60,
}

/**
 * Shared reflection analysis for reflected *and* second-order (stored) XSS checks.
 * Inspects every canary occurrence (bounded) and reports the most exploitable rendering context,
 * so an escaped echo in a filter control cannot mask a raw echo later on the same page.
 */
export function analyzeXssReflection(body: string, mediaType: string, canary: string): ReflectionAnalysis {
  const mediaLower = mediaType.toLowerCase()
  const renderable = mediaLower.includes('html') || mediaLower.includes('svg') || mediaLower.includes('xml') || /^\s*</.test(body)
  if (!canary) {
    return { reflected: false, context: 'html_body', unencodedChars: [], domSinkHint: null, mediaType, renderable, exploitable: false, occurrences: 0 }
  }

  const indexes: number[] = []
  for (let from = 0; indexes.length < MAX_OCCURRENCES;) {
    const found = body.indexOf(canary, from)
    if (found < 0) break
    indexes.push(found)
    from = found + canary.length
  }
  if (indexes.length === 0) {
    return { reflected: false, context: 'html_body', unencodedChars: [], domSinkHint: null, mediaType, renderable, exploitable: false, occurrences: 0 }
  }

  let best: { idx: number; context: ReflectionContext; rawChars: string[]; domSinkHint: string | null; exploitable: boolean; score: number } | null = null
  let first: { idx: number; context: ReflectionContext; rawChars: string[]; domSinkHint: string | null; exploitable: boolean; score: number } | null = null
  for (const idx of indexes) {
    const { rawChars, matched } = analyzeSuffix(body, idx, canary.length)
    const context = classifyContext(body, idx)
    const sinkMatch = /\b(innerHTML|outerHTML|document\.write|eval|Function)\b/i.exec(body.slice(Math.max(0, idx - 200), Math.min(body.length, idx + 200)))
    const domSinkHint = sinkMatch ? sinkMatch[1]! : null
    const inert = insideComment(body, idx)
    const exploitable = !inert && renderable && occurrenceExploitable(context, rawChars, matched, domSinkHint)
    const score = exploitable ? CONTEXT_RANK[context] + (domSinkHint ? 5 : 0) + rawChars.length : -1
    const row = { idx, context, rawChars, domSinkHint, exploitable, score }
    if (!first) first = row
    if (!best || score > best.score) best = row
  }

  const chosen = best && best.exploitable ? best : first!
  return {
    reflected: true,
    context: chosen.context,
    unencodedChars: [...chosen.rawChars],
    domSinkHint: chosen.domSinkHint,
    mediaType,
    renderable,
    exploitable: renderable && Boolean(best?.exploitable),
    occurrences: indexes.length,
    occurrenceIndex: chosen.idx,
  }
}



export async function diffXssContext(ctx: DiffContext): Promise<DiffOutcome> {
  const { req, send, anomalies } = ctx
  const canary = `gxss${randToken(8)}`
  const probeEx = await send(injectParam(req, `${canary}"'<>`))
  if (!probeEx) return { verdict: 'inconclusive', summary: 'XSS context probe request failed.', details: {} }

  const body = probeEx.body
  const analysis = analyzeXssReflection(body, probeEx.mediaType, canary)
  if (!analysis.reflected) {
    return { verdict: 'no_signal', summary: 'Probe marker was not reflected in response.', details: { status: probeEx.status } }
  }
  const { context, unencodedChars, domSinkHint, exploitable, occurrences } = analysis

  if (exploitable) {
    anomalies.push({
      type: 'xss_context',
      context,
      unencodedChars,
      domSinkHint,
      suggestedReplayKind: 'browser_chain',
      suggestedAction: 'dom_xss_sink_hook',
    })
  }

  return {
    verdict: exploitable ? 'signal' : 'no_signal',
    summary: exploitable
      ? `Reflected probe landed in ${context} context with unencoded [${unencodedChars.join(',')}]${domSinkHint ? ` near ${domSinkHint} sink` : ''}${occurrences && occurrences > 1 ? ` (${occurrences} echoes scanned)` : ''}; escalate to browser_chain (dom_xss_sink_hook).`
      : `Probe marker reflected in ${context} context${occurrences && occurrences > 1 ? ` (${occurrences} echoes scanned)` : ''} but dangerous syntax characters were encoded.`,
    details: {
      reflected: true,
      context,
      unencodedChars,
      domSinkHint,
      mediaType: probeEx.mediaType,
      occurrences,
      suggestedReplayKind: 'browser_chain',
      suggestedAction: 'dom_xss_sink_hook',
    },
  }
}

export const xssProbe: ProbeModule = {
  family: 'xss',
  classes: ['xss_context'],
  run: (ctx) => diffXssContext(ctx),
}
