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
}



/**
 * Shared reflection analysis for reflected *and* second-order (stored) XSS checks.
 * Locates `canary` in `body` and classifies the surrounding rendering context.
 */
export function analyzeXssReflection(body: string, mediaType: string, canary: string): ReflectionAnalysis {
  const idx = body.indexOf(canary)
  const mediaLower = mediaType.toLowerCase()
  const renderable = mediaLower.includes('html') || mediaLower.includes('svg') || mediaLower.includes('xml') || /^\s*</.test(body)
  if (idx < 0) {
    return { reflected: false, context: 'html_body', unencodedChars: [], domSinkHint: null, mediaType, renderable, exploitable: false }
  }

  const windowStart = Math.max(0, idx - 200)
  const before = body.slice(windowStart, idx)
  const snippet = body.slice(idx, Math.min(body.length, idx + canary.length + 16))
  const unencodedChars: string[] = []
  for (const ch of ['"', "'", '<', '>']) {
    if (snippet.includes(ch)) unencodedChars.push(ch)
  }

  let context: ReflectionContext = 'html_body'
  if (/\bon[a-z]+\s*=\s*["']?[^"'>]*$/i.test(before)) {
    context = 'event_handler_attr'
  } else if (/\b(?:href|src|action|formaction)\s*=\s*["']?[^"'>]*$/i.test(before)) {
    context = 'href_url'
  } else if (/<script\b[^>]*>[\s\S]*$/i.test(before) && !/<\/script>/i.test(before.slice(before.lastIndexOf('<script')))) {
    context = 'js_string'
  } else if (/<[a-zA-Z0-9_-]+(?:\s+[^>]*)?\s+[a-zA-Z0-9_:-]+\s*=\s*["']?[^"'>]*$/i.test(before)) {
    context = 'html_attr'
  }

  const sinkMatch = /\b(innerHTML|outerHTML|document\.write|eval|Function)\b/i.exec(body.slice(Math.max(0, idx - 200), Math.min(body.length, idx + 200)))
  const domSinkHint = sinkMatch ? sinkMatch[1] : null

  const exploitable =
    renderable && (
      (context === 'html_body' && (unencodedChars.includes('<') || unencodedChars.includes('>') || Boolean(domSinkHint))) ||
      (context === 'html_attr' && (unencodedChars.includes('"') || unencodedChars.includes("'"))) ||
      (context === 'js_string' && (unencodedChars.includes('"') || unencodedChars.includes("'") || unencodedChars.includes('<') || Boolean(domSinkHint))) ||
      context === 'href_url' ||
      context === 'event_handler_attr' ||
      Boolean(domSinkHint)
    )

  return { reflected: true, context, unencodedChars, domSinkHint, mediaType, renderable, exploitable }
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
  const { context, unencodedChars, domSinkHint, exploitable } = analysis

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
      ? `Reflected probe landed in ${context} context with unencoded [${unencodedChars.join(',')}]${domSinkHint ? ` near ${domSinkHint} sink` : ''}; escalate to browser_chain (dom_xss_sink_hook).`
      : `Probe marker reflected in ${context} context but dangerous syntax characters were encoded.`,
    details: {
      reflected: true,
      context,
      unencodedChars,
      domSinkHint,
      mediaType: probeEx.mediaType,
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
