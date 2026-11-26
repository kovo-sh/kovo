/**
 * Pure, isomorphic `Copy as cURL` parser (zero Node built-ins; safe on both server and client).
 *
 * Extracts target origin, HTTP method, `Cookie` header (including `-b` / `--cookie`),
 * `Authorization` header (including `-u` / `--user` Basic auth and Bearer tokens), and custom
 * auth headers from pasted DevTools `"Copy as cURL"` commands (bash, zsh, POSIX, Windows cmd).
 */

export interface ParsedCurlHeader {
  name: string
  value: string
}

export interface RecommendedCurlCredential {
  authKind: 'cookie' | 'bearer' | 'header'
  headerName?: string
  secret: string
  summary: string
}

export interface ParsedCurlCommand {
  url?: string
  origin?: string
  method?: string
  /** Combined `Cookie` header value merged from `-H 'Cookie: ...'` and `-b` / `--cookie`. */
  cookie?: string
  /** Parsed cookie name -> value map. */
  cookies: Record<string, string>
  /** Raw `Authorization` header value (including Basic synthesized from `-u`/`--user`). */
  authorization?: string
  /** Extracted Bearer token when `Authorization: Bearer <token>` is present. */
  bearerToken?: string
  /** Non-noise custom headers (e.g. `X-Api-Key`, `X-CSRF-Token`, `X-Tenant-Id`, etc.). */
  customHeaders: Record<string, string>
  /** All parsed headers in original order. */
  allHeaders: ParsedCurlHeader[]
  /** Single primary credential projection for quick form population. */
  recommended?: RecommendedCurlCredential
}

const IGNORED_BROWSER_HEADERS = new Set([
  'host',
  'user-agent',
  'accept',
  'accept-encoding',
  'accept-language',
  'content-type',
  'content-length',
  'referer',
  'origin',
  'connection',
  'cache-control',
  'pragma',
  'priority',
  'dnt',
  'upgrade-insecure-requests',
  'te',
  'if-none-match',
  'if-modified-since',
  'x-requested-with',
  'cookie',
  'authorization',
])

const PREFERRED_AUTH_HEADER_PATTERN = /^(?:x-api-key|api-key|apikey|x-auth-token|x-access-token|x-session-token|x-csrf-token|x-xsrf-token|x-token|x-supabase-api-key)$/i

/** cURL options that consume a following argument (so their values are never mistaken for the URL). */
const CURL_OPTIONS_WITH_ARG = new Set([
  '-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json',
  '-A', '--user-agent',
  '-e', '--referer',
  '-o', '--output',
  '-F', '--form', '--form-string',
  '-x', '--proxy', '--proxy-user', '-U',
  '-c', '--cookie-jar',
  '-m', '--max-time', '--connect-timeout',
  '-w', '--write-out',
  '-E', '--cert', '--key', '--cacert',
  '--resolve', '--connect-to', '--interface', '--max-redirs',
  '--retry', '--retry-delay', '--retry-max-time',
])

function encodeBase64Utf8(text: string): string {
  if (typeof Buffer !== 'undefined') {
    return Buffer.from(text, 'utf8').toString('base64')
  }
  const bytes = new TextEncoder().encode(text)
  let binary = ''
  for (let i = 0; i < bytes.length; i += 1) {
    binary += String.fromCharCode(bytes[i]!)
  }
  return btoa(binary)
}

function decodeAnsiCEscape(input: string, index: number): { char: string; nextIndex: number } {
  const ch = input[index]
  if (ch === undefined) return { char: '\\', nextIndex: index }
  switch (ch) {
    case 'a': return { char: '\x07', nextIndex: index + 1 }
    case 'b': return { char: '\b', nextIndex: index + 1 }
    case 'e':
    case 'E': return { char: '\x1b', nextIndex: index + 1 }
    case 'f': return { char: '\f', nextIndex: index + 1 }
    case 'n': return { char: '\n', nextIndex: index + 1 }
    case 'r': return { char: '\r', nextIndex: index + 1 }
    case 't': return { char: '\t', nextIndex: index + 1 }
    case 'v': return { char: '\v', nextIndex: index + 1 }
    case '\\': return { char: '\\', nextIndex: index + 1 }
    case '\'': return { char: '\'', nextIndex: index + 1 }
    case '"': return { char: '"', nextIndex: index + 1 }
    case '?': return { char: '?', nextIndex: index + 1 }
    case 'x': {
      const hex = /^[0-9a-fA-F]{1,2}/.exec(input.slice(index + 1))
      if (hex) {
        return { char: String.fromCharCode(parseInt(hex[0], 16)), nextIndex: index + 1 + hex[0].length }
      }
      return { char: '\\x', nextIndex: index + 1 }
    }
    case 'u': {
      const hex = /^[0-9a-fA-F]{1,4}/.exec(input.slice(index + 1))
      if (hex) {
        return { char: String.fromCodePoint(parseInt(hex[0], 16)), nextIndex: index + 1 + hex[0].length }
      }
      return { char: '\\u', nextIndex: index + 1 }
    }
    case 'U': {
      const hex = /^[0-9a-fA-F]{1,8}/.exec(input.slice(index + 1))
      if (hex) {
        const cp = parseInt(hex[0], 16)
        if (cp <= 0x10ffff) {
          return { char: String.fromCodePoint(cp), nextIndex: index + 1 + hex[0].length }
        }
      }
      return { char: '\\U', nextIndex: index + 1 }
    }
    default: {
      if (ch >= '0' && ch <= '7') {
        const oct = /^[0-7]{1,3}/.exec(input.slice(index))
        if (oct) {
          return { char: String.fromCharCode(parseInt(oct[0], 8) & 0xff), nextIndex: index + oct[0].length }
        }
      }
      return { char: `\\${ch}`, nextIndex: index + 1 }
    }
  }
}

/**
 * POSIX/bash-compatible shell argument tokenizer supporting single quotes (`'...'`),
 * double quotes (`"..."`), ANSI-C quotes (`$'...'`), backslash line continuations (`\\\n`),
 * Windows cmd caret continuations (`^\n`), and adjacent token concatenation (`'a'\''b'`).
 */
export function tokenizeCurlArgs(raw: string): string[] {
  const isCmdCurl = /^\s*curl(?:\.exe)?\s+/i.test(raw) && /\^\s*\r?\n/.test(raw)
  const input = isCmdCurl
    ? raw
        .replace(/\^\r?\n/g, ' ')
        .replace(/\\\^"/g, '\\"')
        .replace(/\^"/g, '"')
        .replace(/\^%/g, '%')
        .replace(/\^\^/g, '^')
    : raw

  const tokens: string[] = []
  let current = ''
  let hasToken = false
  let i = 0
  const len = input.length

  while (i < len) {
    const ch = input[i]!

    // Backslash line continuation outside quotes
    if (ch === '\\' && (input[i + 1] === '\n' || (input[i + 1] === '\r' && input[i + 2] === '\n'))) {
      i += input[i + 1] === '\r' ? 3 : 2
      continue
    }

    if (/\s/.test(ch)) {
      if (hasToken) {
        tokens.push(current)
        current = ''
        hasToken = false
      }
      i += 1
      continue
    }

    // ANSI-C quoting: $'...'
    if (ch === '$' && input[i + 1] === '\'') {
      hasToken = true
      i += 2
      while (i < len) {
        const c = input[i]!
        if (c === '\'') {
          i += 1
          break
        }
        if (c === '\\') {
          const decoded = decodeAnsiCEscape(input, i + 1)
          current += decoded.char
          i = decoded.nextIndex
        } else {
          current += c
          i += 1
        }
      }
      continue
    }

    // Single quotes: '...'
    if (ch === '\'') {
      hasToken = true
      i += 1
      while (i < len && input[i] !== '\'') {
        current += input[i]!
        i += 1
      }
      if (i < len && input[i] === '\'') i += 1
      continue
    }

    // Double quotes: "..."
    if (ch === '"') {
      hasToken = true
      i += 1
      while (i < len) {
        const c = input[i]!
        if (c === '"') {
          i += 1
          break
        }
        if (c === '\\') {
          const next = input[i + 1]
          if (next === '\n') {
            i += 2
            continue
          }
          if (next === '\r' && input[i + 2] === '\n') {
            i += 3
            continue
          }
          if (next === '"' || next === '\\' || next === '$' || next === '`') {
            current += next
            i += 2
            continue
          }
          current += '\\'
          i += 1
          continue
        }
        current += c
        i += 1
      }
      continue
    }

    // Backslash escape outside quotes
    if (ch === '\\') {
      hasToken = true
      if (i + 1 < len) {
        current += input[i + 1]!
        i += 2
      } else {
        i += 1
      }
      continue
    }

    hasToken = true
    current += ch
    i += 1
  }

  if (hasToken) tokens.push(current)
  return tokens
}

function parseUrlInfo(candidate: string): { url: string; origin: string } | null {
  const trimmed = candidate.trim()
  if (!/^https?:\/\//i.test(trimmed)) return null
  try {
    const parsed = new URL(trimmed)
    return { url: parsed.toString(), origin: parsed.origin }
  } catch {
    return null
  }
}

function parseHeaderLine(rawHeader: string): ParsedCurlHeader | null {
  const colon = rawHeader.indexOf(':')
  if (colon <= 0) return null
  const name = rawHeader.slice(0, colon).trim()
  const value = rawHeader.slice(colon + 1).trim()
  if (!name || !/^[A-Za-z0-9-]+$/.test(name) || !value) return null
  return { name, value }
}

function isIgnoredCustomHeader(name: string): boolean {
  const lower = name.toLowerCase()
  return IGNORED_BROWSER_HEADERS.has(lower) || lower.startsWith('sec-')
}

function parseCookiePairs(cookieHeader: string): Record<string, string> {
  const out: Record<string, string> = {}
  for (const part of cookieHeader.split(';')) {
    const eq = part.indexOf('=')
    if (eq <= 0) continue
    const name = part.slice(0, eq).trim()
    const value = part.slice(eq + 1).trim()
    if (!name || /[\r\n\0]/.test(value)) continue
    out[name] = value
  }
  return out
}

function buildParsedResult(params: {
  url?: string
  origin?: string
  method?: string
  headers: ParsedCurlHeader[]
  cookieParts: string[]
}): ParsedCurlCommand | null {
  const { url, origin, method, headers, cookieParts } = params

  let authorization: string | undefined
  let bearerToken: string | undefined
  const allCookies: string[] = []
  const customHeaders: Record<string, string> = {}

  for (const h of headers) {
    const lower = h.name.toLowerCase()
    if (lower === 'authorization') {
      authorization = h.value
      const bearerMatch = /^bearer\s+(.+)$/i.exec(h.value)
      if (bearerMatch?.[1]?.trim()) {
        bearerToken = bearerMatch[1].trim()
      }
      continue
    }
    if (lower === 'cookie') {
      if (h.value.trim()) allCookies.push(h.value.trim())
      continue
    }
    if (!isIgnoredCustomHeader(h.name)) {
      customHeaders[h.name] = h.value
    }
  }

  for (const part of cookieParts) {
    const trimmed = part.trim()
    if (trimmed) allCookies.push(trimmed)
  }

  const cookie = allCookies.length > 0 ? allCookies.join('; ') : undefined
  const cookies = cookie ? parseCookiePairs(cookie) : {}

  // Build primary credential recommendation: Bearer -> Cookie -> Authorization header -> Custom auth header
  let recommended: RecommendedCurlCredential | undefined
  if (bearerToken) {
    recommended = {
      authKind: 'bearer',
      secret: bearerToken,
      summary: `Extracted Bearer token${origin ? ` for ${origin}` : ''}.`,
    }
  } else if (cookie) {
    const names = Object.keys(cookies)
    recommended = {
      authKind: 'cookie',
      secret: cookie,
      summary: `Extracted ${names.length} cookie${names.length === 1 ? '' : 's'}${names.length ? ` (${names.slice(0, 4).join(', ')}${names.length > 4 ? '…' : ''})` : ''}${origin ? ` for ${origin}` : ''}.`,
    }
  } else if (authorization) {
    recommended = {
      authKind: 'header',
      headerName: 'Authorization',
      secret: authorization,
      summary: `Extracted Authorization header${origin ? ` for ${origin}` : ''}.`,
    }
  } else {
    const customEntries = Object.entries(customHeaders)
    const preferred = customEntries.find(([name]) => PREFERRED_AUTH_HEADER_PATTERN.test(name))
    const chosen = preferred ?? customEntries[0]
    if (chosen) {
      recommended = {
        authKind: 'header',
        headerName: chosen[0],
        secret: chosen[1],
        summary: `Extracted ${chosen[0]} header${origin ? ` for ${origin}` : ''}.`,
      }
    }
  }

  if (!url && !origin && !cookie && !authorization && Object.keys(customHeaders).length === 0) {
    return null
  }

  return {
    ...(url ? { url } : {}),
    ...(origin ? { origin } : {}),
    ...(method ? { method } : {}),
    ...(cookie ? { cookie } : {}),
    cookies,
    ...(authorization ? { authorization } : {}),
    ...(bearerToken ? { bearerToken } : {}),
    customHeaders,
    allHeaders: headers,
    ...(recommended ? { recommended } : {}),
  }
}

/**
 * Parse a browser DevTools `"Copy as cURL"` command into structured origin, cookies,
 * Authorization header / Bearer token, and custom auth headers.
 */
export function parseCurlCommand(raw: string): ParsedCurlCommand | null {
  const trimmed = raw.trim()
  if (!trimmed) return null
  const args = tokenizeCurlArgs(trimmed)
  if (args.length === 0) return null
  const first = args[0]!.toLowerCase()
  if (first !== 'curl' && first !== 'curl.exe') return null

  const headers: ParsedCurlHeader[] = []
  const cookieParts: string[] = []
  let urlInfo: { url: string; origin: string } | null = null
  let method: string | undefined

  const pushHeader = (rawVal: string) => {
    const parsed = parseHeaderLine(rawVal)
    if (parsed) headers.push(parsed)
  }

  const pushBasicAuth = (userPass: string) => {
    const cleaned = userPass.trim()
    if (!cleaned) return
    const encoded = encodeBase64Utf8(cleaned.includes(':') ? cleaned : `${cleaned}:`)
    headers.push({ name: 'Authorization', value: `Basic ${encoded}` })
  }

  for (let i = 1; i < args.length; i += 1) {
    const arg = args[i]!

    if (arg === '--') {
      const next = args[i + 1]
      if (!urlInfo && next) urlInfo = parseUrlInfo(next)
      break
    }

    if (arg === '-X' || arg === '--request') {
      const val = args[i + 1]
      if (val !== undefined) {
        method = val.trim().toUpperCase()
        i += 1
      }
      continue
    }
    if (arg.startsWith('--request=')) {
      method = arg.slice('--request='.length).trim().toUpperCase()
      continue
    }
    if (arg.startsWith('-X') && arg.length > 2) {
      method = arg.slice(2).trim().toUpperCase()
      continue
    }

    if (arg === '-H' || arg === '--header') {
      const val = args[i + 1]
      if (val !== undefined) {
        pushHeader(val)
        i += 1
      }
      continue
    }
    if (arg.startsWith('--header=')) {
      pushHeader(arg.slice('--header='.length))
      continue
    }
    if (arg.startsWith('-H') && arg.length > 2) {
      pushHeader(arg.slice(2))
      continue
    }

    if (arg === '-b' || arg === '--cookie') {
      const val = args[i + 1]
      if (val !== undefined) {
        if (val.includes('=')) cookieParts.push(val.trim())
        i += 1
      }
      continue
    }
    if (arg.startsWith('--cookie=')) {
      const val = arg.slice('--cookie='.length).trim()
      if (val.includes('=')) cookieParts.push(val)
      continue
    }
    if (arg.startsWith('-b') && arg.length > 2) {
      const val = arg.slice(2).trim()
      if (val.includes('=')) cookieParts.push(val)
      continue
    }

    if (arg === '-u' || arg === '--user') {
      const val = args[i + 1]
      if (val !== undefined) {
        pushBasicAuth(val)
        i += 1
      }
      continue
    }
    if (arg.startsWith('--user=')) {
      pushBasicAuth(arg.slice('--user='.length))
      continue
    }
    if (arg.startsWith('-u') && arg.length > 2) {
      pushBasicAuth(arg.slice(2))
      continue
    }

    if (arg === '--url') {
      const val = args[i + 1]
      if (val !== undefined) {
        if (!urlInfo) urlInfo = parseUrlInfo(val)
        i += 1
      }
      continue
    }
    if (arg.startsWith('--url=')) {
      if (!urlInfo) urlInfo = parseUrlInfo(arg.slice('--url='.length))
      continue
    }

    if (CURL_OPTIONS_WITH_ARG.has(arg)) {
      i += 1
      continue
    }

    if (arg.startsWith('-')) {
      continue
    }

    if (!urlInfo) {
      urlInfo = parseUrlInfo(arg)
    }
  }

  return buildParsedResult({
    url: urlInfo?.url,
    origin: urlInfo?.origin,
    method,
    headers,
    cookieParts,
  })
}

/**
 * Convenience parser accepting either a full `curl ...` command, raw HTTP headers
 * (`Cookie: ...`, `Authorization: Bearer ...`), or bare `name=value; name2=value2` cookie pairs.
 */
export function parseCurlOrHeaderInput(raw: string): ParsedCurlCommand | null {
  const input = raw.trim()
  if (!input) return null

  if (/^curl(?:\.exe)?(?:\s|$)/i.test(input)) {
    return parseCurlCommand(input)
  }

  let urlInfo: { url: string; origin: string } | null = null
  const urlMatch = input.match(/https?:\/\/[a-z0-9.-]+(?::\d+)?(?:\/[^\s'"]*)?/i)
  if (urlMatch) {
    urlInfo = parseUrlInfo(urlMatch[0])
  }

  const lines = input.split(/\r?\n/).map(l => l.trim()).filter(Boolean)
  const headers: ParsedCurlHeader[] = []
  for (const line of lines) {
    const parsed = parseHeaderLine(line)
    if (parsed) headers.push(parsed)
  }
  if (headers.length > 0) {
    const built = buildParsedResult({
      url: urlInfo?.url,
      origin: urlInfo?.origin,
      headers,
      cookieParts: [],
    })
    if (built?.recommended) return built
  }

  if (input.includes('=')) {
    return buildParsedResult({
      url: urlInfo?.url,
      origin: urlInfo?.origin,
      headers: [],
      cookieParts: [input],
    })
  }

  return null
}
