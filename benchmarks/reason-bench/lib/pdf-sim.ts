// Simulated server-side HTML -> PDF text renderer. Bounded, pure JS: no eval / Function / vm and no
// real filesystem. The "renderer" tokenizes HTML, strips markup, decodes a small entity table and
// extracts text. Its server-side fetch seam (images/iframes/`{{fetch:URL}}` placeholders) goes
// through lib/egress.ts, so an attacker-controlled internal URL is recorded as ssrf_internal_fetch
// by the egress guard while the PDF worker itself stays contained.
import type { Egress } from './egress.ts'
import type { Oracle } from './oracle.ts'

const MAX_HTML = 256 * 1024
const MAX_TEXT = 64 * 1024
const MAX_FETCHES = 4
const MAX_FETCH_BODY = 4096
const PAGE_CHARS = 3000

const ENTITIES: Record<string, string> = {
  amp: '&', lt: '<', gt: '>', quot: '"', apos: "'", nbsp: ' ',
  copy: '(c)', reg: '(r)', hellip: '...', mdash: '-', ndash: '-',
}

export interface PdfRenderOptions {
  oracle?: Oracle
  egress?: Egress
  maxFetches?: number
}

export interface PdfFetchObservation {
  url: string
  status: number
  bytes: number
  preview: string
}

export interface PdfDocument {
  pages: string[]
  text: string
  fetches: PdfFetchObservation[]
  truncated: boolean
}

/** Decode the small, fixed entity table above plus numeric references (bounded). */
export function decodeEntities(s: string): string {
  return s.replace(/&(#x?[0-9a-fA-F]+|[a-zA-Z]+);/g, (whole, ref: string) => {
    if (ref[0] === '#') {
      const code = ref[1] === 'x' || ref[1] === 'X' ? parseInt(ref.slice(2), 16) : parseInt(ref.slice(1), 10)
      if (!Number.isFinite(code) || code < 0 || code > 0x10ffff) return whole
      try { return String.fromCodePoint(code) } catch { return whole }
    }
    return ENTITIES[ref.toLowerCase()] ?? whole
  })
}

/** Strip tags/comments/script/style and collapse whitespace; bounded by MAX_TEXT. */
export function htmlToPlainText(html: string): { text: string; truncated: boolean } {
  let src = html.slice(0, MAX_HTML)
  src = src.replace(/<!--[\s\S]*?-->/g, ' ')
  src = src.replace(/<(script|style)\b[^>]*>[\s\S]*?<\/\1\s*>/gi, ' ')
  src = src.replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li|tr|h[1-6]|section|article)\s*>/gi, '\n')
  src = src.replace(/<[^>]*>/g, ' ')
  let text = decodeEntities(src).replace(/[ \t\f\v]+/g, ' ').replace(/\n{3,}/g, '\n\n').trim()
  const truncated = text.length > MAX_TEXT
  if (truncated) text = text.slice(0, MAX_TEXT)
  return { text, truncated }
}

/** Extract server-side fetch targets: src/href attributes and explicit `{{fetch:URL}}` marks. */
export function extractFetchUrls(html: string): string[] {
  const out: string[] = []
  const attr = /\b(?:src|href)\s*=\s*["'](https?:\/\/[^"']+)["']/gi
  let m: RegExpExecArray | null
  while ((m = attr.exec(html)) !== null) out.push(m[1]!)
  const tpl = /\{\{\s*fetch\s*:\s*(https?:\/\/[^}\s]+)\s*\}\}/gi
  while ((m = tpl.exec(html)) !== null) out.push(m[1]!)
  return [...new Set(out)]
}

/** Split rendered text into deterministic page-sized chunks. */
export function paginate(text: string, pageChars = PAGE_CHARS): string[] {
  if (text.length === 0) return ['']
  const pages: string[] = []
  for (let i = 0; i < text.length; i += pageChars) pages.push(text.slice(i, i + pageChars))
  return pages
}

/**
 * Render an HTML report to PDF text and, when an egress seam is supplied, resolve the document's
 * server-side fetch targets (images, iframes, `{{fetch:...}}`). Every target flows through
 * lib/egress.ts; internal-URL fetches emit ssrf_internal_fetch there. Fetch failures are recorded,
 * never thrown, so the renderer stays available and bounded.
 */
export async function renderPdfReport(html: string, opts: PdfRenderOptions = {}): Promise<PdfDocument> {
  const { text, truncated } = htmlToPlainText(html)
  const fetches: PdfFetchObservation[] = []
  if (opts.egress) {
    const urls = extractFetchUrls(html).slice(0, opts.maxFetches ?? MAX_FETCHES)
    for (const url of urls) {
      try {
        const res = await opts.egress.fetch(url, { inputDerived: true })
        fetches.push({
          url,
          status: res.status,
          bytes: res.body.length,
          preview: res.body.slice(0, MAX_FETCH_BODY),
        })
      } catch (err) {
        fetches.push({ url, status: 0, bytes: 0, preview: `blocked: ${(err as Error).message.slice(0, 120)}` })
      }
    }
  }
  return { pages: paginate(text), text, fetches, truncated }
}

/** Synchronous, fetch-free variant used by callers that only need page text. */
export function htmlToPdfText(html: string): PdfDocument {
  const { text, truncated } = htmlToPlainText(html)
  return { pages: paginate(text), text, fetches: [], truncated }
}
