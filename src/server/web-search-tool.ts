/**
 * Bounded, read-only web search tool (`src/server/web-search-tool.ts`) for the decoupled Exploiter.
 * Routes all live outbound calls through `EgressGateway` (`egressFetch`, HTTPS-only, SSRF-safe);
 * never sends cookies, credentials, or secrets; caps timeout <= 10s and results <= 5.
 */
import { egressFetch } from './egress-gateway.ts'

export interface WebSearchArgs { query: string; domains?: string[]; maxResults?: number }
export interface WebSearchResultItem { title: string; url: string; snippet: string }
export interface WebSearchResponse { ok: boolean; query: string; results: WebSearchResultItem[]; error?: string }
export interface WebSearchOptions { fetchImpl?: typeof fetch; timeoutMs?: number; endpoint?: string; signal?: AbortSignal }

const DEFAULT_TIMEOUT_MS = 8_000, MAX_TIMEOUT_MS = 10_000, MIN_TIMEOUT_MS = 500
const DEFAULT_MAX_RESULTS = 5, MAX_RESULTS_CAP = 5, MAX_QUERY_CHARS = 300
const MAX_TITLE_CHARS = 200, MAX_SNIPPET_CHARS = 400, MAX_URL_CHARS = 500, MAX_RESPONSE_BYTES = 512 * 1024
const DEFAULT_DDG_HTML_ENDPOINT = 'https://html.duckduckgo.com/html/'
const DOMAIN_RE = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)+$/i

/** Default false when `KOVO_BENCH_MODE=1` or `runAllowWebSearch === false`, true otherwise. */
export function resolveAllowWebSearch(input: { runAllowWebSearch?: boolean; env?: NodeJS.ProcessEnv }): boolean {
  if (input.runAllowWebSearch === false) return false
  return (input.env ?? process.env).KOVO_BENCH_MODE !== '1'
}

function decodeHtmlEntities(raw: string): string {
  return raw
    .replace(/&amp;/gi, '&').replace(/&lt;/gi, '<').replace(/&gt;/gi, '>')
    .replace(/&quot;/gi, '"').replace(/&#39;|&apos;/gi, "'").replace(/&nbsp;/gi, ' ')
    .replace(/&#x([0-9a-f]+);/gi, (_m, hex: string) => {
      const cp = Number.parseInt(hex, 16)
      return Number.isFinite(cp) && cp >= 32 && cp <= 0x10ffff ? String.fromCodePoint(cp) : ' '
    })
    .replace(/&#(\d+);/g, (_m, dec: string) => {
      const cp = Number.parseInt(dec, 10)
      return Number.isFinite(cp) && cp >= 32 && cp <= 0x10ffff ? String.fromCodePoint(cp) : ' '
    })
}

function sanitizeText(raw: string, maxChars: number): string {
  const cleaned = decodeHtmlEntities(raw.replace(/<[^>]*>/g, ' '))
    .replace(/[\x00-\x1f\x7f]/g, ' ').replace(/\s+/g, ' ').trim()
  return cleaned.length <= maxChars ? cleaned : `${cleaned.slice(0, maxChars - 1)}…`
}

function normalizeResultUrl(rawUrl: string): string | null {
  const decoded = decodeHtmlEntities(rawUrl).replace(/[\x00-\x1f\x7f]/g, '').trim()
  if (!decoded) return null
  try {
    let candidate = decoded.startsWith('//') ? `https:${decoded}` : decoded
    if (candidate.startsWith('/l/?') || candidate.includes('duckduckgo.com/l/?')) {
      const target = new URL(candidate, 'https://duckduckgo.com').searchParams.get('uddg')
      if (target) candidate = target
    }
    const parsed = new URL(candidate)
    return parsed.protocol === 'http:' || parsed.protocol === 'https:' ? parsed.toString().slice(0, MAX_URL_CHARS) : null
  } catch { return null }
}

function parseJsonResults(payload: unknown): WebSearchResultItem[] {
  const list = Array.isArray(payload) ? payload
    : payload && typeof payload === 'object'
      ? ((payload as Record<string, unknown>).results ?? (payload as Record<string, unknown>).items ?? (payload as Record<string, unknown>).data)
      : undefined
  if (!Array.isArray(list)) return []
  const out: WebSearchResultItem[] = []
  for (const item of list) {
    if (!item || typeof item !== 'object') continue
    const rec = item as Record<string, unknown>
    const url = normalizeResultUrl(String(rec.url ?? rec.href ?? rec.link ?? ''))
    const title = sanitizeText(String(rec.title ?? rec.name ?? ''), MAX_TITLE_CHARS)
    const snippet = sanitizeText(String(rec.snippet ?? rec.description ?? rec.content ?? rec.body ?? ''), MAX_SNIPPET_CHARS)
    if (url && (title || snippet)) out.push({ title: title || url, url, snippet })
  }
  return out
}

function parseDuckDuckGoHtml(html: string): WebSearchResultItem[] {
  const out: WebSearchResultItem[] = []
  const linkRe = /<a\b[^>]*class="[^"]*(?:result__a|result-link)[^"]*"[^>]*href="([^"]+)"[^>]*>([\s\S]*?)<\/a>/gi
  const snipRe = /<(?:a|div|td|span)\b[^>]*class="[^"]*(?:result__snippet|result-snippet)[^"]*"[^>]*>([\s\S]*?)<\/(?:a|div|td|span)>/gi
  const snippets: Array<{ index: number; text: string }> = []
  let sm: RegExpExecArray | null
  while ((sm = snipRe.exec(html)) !== null) snippets.push({ index: sm.index, text: sanitizeText(sm[1] ?? '', MAX_SNIPPET_CHARS) })
  let lm: RegExpExecArray | null
  while ((lm = linkRe.exec(html)) !== null) {
    const url = normalizeResultUrl(lm[1] ?? ''), title = sanitizeText(lm[2] ?? '', MAX_TITLE_CHARS)
    if (!url || !title) continue
    const nextSnip = snippets.find(s => s.index > lm!.index && s.index - lm!.index < 4000)?.text ?? ''
    out.push({ title, url, snippet: nextSnip })
  }
  return out
}

function matchesRequestedDomains(urlStr: string, domains: readonly string[]): boolean {
  if (domains.length === 0) return true
  try {
    const host = new URL(urlStr).hostname.toLowerCase()
    return domains.some(d => host === d || host.endsWith(`.${d}`))
  } catch { return false }
}

export async function executeWebSearch(args: WebSearchArgs, opts: WebSearchOptions = {}): Promise<WebSearchResponse> {
  const cleanQuery = sanitizeText(String(args.query ?? ''), MAX_QUERY_CHARS)
  if (!cleanQuery) return { ok: false, query: '', results: [], error: 'Web search query must be non-empty.' }
  const domains = (args.domains ?? [])
    .map(d => String(d).trim().toLowerCase().replace(/^https?:\/\//, '').split('/')[0] ?? '')
    .filter(d => DOMAIN_RE.test(d)).slice(0, 5)
  const maxResults = Math.max(1, Math.min(MAX_RESULTS_CAP, Math.floor(args.maxResults ?? DEFAULT_MAX_RESULTS)))
  const timeoutMs = Math.max(MIN_TIMEOUT_MS, Math.min(MAX_TIMEOUT_MS, Math.floor(opts.timeoutMs ?? DEFAULT_TIMEOUT_MS)))
  const effectiveQuery = domains.length > 0
    ? `${cleanQuery} ${domains.slice(0, 3).map(d => `site:${d}`).join(' OR ')}`.slice(0, MAX_QUERY_CHARS)
    : cleanQuery
  const baseEndpoint = (opts.endpoint ?? process.env.KOVO_WEB_SEARCH_ENDPOINT ?? '').trim() || DEFAULT_DDG_HTML_ENDPOINT
  const requestUrl = `${baseEndpoint}${baseEndpoint.includes('?') ? '&' : '?'}q=${encodeURIComponent(effectiveQuery)}`
  if (opts.signal?.aborted) return { ok: false, query: cleanQuery, results: [], error: 'Web search aborted.' }

  const controller = new AbortController()
  const onOuterAbort = () => controller.abort(opts.signal?.reason ?? 'aborted')
  opts.signal?.addEventListener('abort', onOuterAbort, { once: true })
  const timer = setTimeout(() => controller.abort(new Error(`timeout after ${timeoutMs}ms`)), timeoutMs)
  try {
    const reqInit: RequestInit = {
      method: 'GET', redirect: 'follow', credentials: 'omit', signal: controller.signal,
      headers: { Accept: 'application/json, text/html;q=0.9', 'User-Agent': 'Kovo-Research/1.0' },
    }
    const res = opts.fetchImpl
      ? await opts.fetchImpl(requestUrl, reqInit)
      : await egressFetch(requestUrl, reqInit, {
          allowLocalLab: false, allowHttp: false, followRedirects: true,
          maxRedirects: 3, timeoutMs, maxResponseBytes: MAX_RESPONSE_BYTES, rejectUnauthorized: true,
        })
    if (!res.ok) return { ok: false, query: cleanQuery, results: [], error: `Web search unavailable: upstream HTTP ${res.status}.` }
    const rawBody = (await res.text()).slice(0, MAX_RESPONSE_BYTES)
    const contentType = (res.headers.get('content-type') ?? '').toLowerCase()
    let parsed: WebSearchResultItem[] = []
    if (contentType.includes('application/json') || /^\s*[{[]/.test(rawBody)) {
      try { parsed = parseJsonResults(JSON.parse(rawBody)) } catch { parsed = parseDuckDuckGoHtml(rawBody) }
    } else parsed = parseDuckDuckGoHtml(rawBody)
    const deduped: WebSearchResultItem[] = [], seen = new Set<string>()
    for (const item of parsed) {
      if (seen.has(item.url) || !matchesRequestedDomains(item.url, domains)) continue
      seen.add(item.url); deduped.push(item)
      if (deduped.length >= maxResults) break
    }
    return { ok: true, query: cleanQuery, results: deduped }
  } catch (err) {
    const msg = err instanceof Error ? err.message : String(err)
    return { ok: false, query: cleanQuery, results: [], error: `Web search unavailable (offline or timeout): ${sanitizeText(msg, 180)}` }
  } finally {
    clearTimeout(timer)
    opts.signal?.removeEventListener('abort', onOuterAbort)
  }
}
