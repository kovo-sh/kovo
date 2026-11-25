export interface ParsedCurlCredentials {
  origin?: string
  authKind: 'cookie' | 'bearer' | 'header'
  headerName?: string
  secret: string
  summary: string
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
])

const PREFERRED_AUTH_HEADER_PATTERN = /^(?:authorization|x-api-key|api-key|apikey|x-auth-token|x-access-token|x-session-token|x-csrf-token|x-xsrf-token|x-token|x-supabase-api-key)$/i

/** cURL options that consume a following argument (so their values are never mistaken for the target URL). */
const CURL_OPTIONS_WITH_ARG = new Set([
  '-X', '--request',
  '-d', '--data', '--data-raw', '--data-binary', '--data-ascii', '--data-urlencode', '--json',
  '-A', '--user-agent',
  '-e', '--referer',
  '-u', '--user',
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
export function tokenizeShellArgs(raw: string): string[] {
  // Normalize Windows cmd caret line continuations (`^` at end of line) and `^"` escapes when present.
  const isCmdCurl = /^\s*curl(?:\.exe)?\s+/i.test(raw) && /\^\s*\r?\n/.test(raw)
  const input = isCmdCurl
    ? raw.replace(/\^\r?\n/g, ' ').replace(/\^"/g, '\\"').replace(/\^%/g, '%').replace(/\^\^/g, '^')
    : raw

  const tokens: string[] = []
  let current = ''
  let hasToken = false
  let i = 0
  const len = input.length

  while (i < len) {
    const ch = input[i]!

    // Line continuation outside quotes: `\<LF>` or `\<CR><LF>`
    if (ch === '\\' && (input[i + 1] === '\n' || (input[i + 1] === '\r' && input[i + 2] === '\n'))) {
      i += input[i + 1] === '\r' ? 3 : 2
      continue
    }

    // Whitespace delimits tokens
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

  if (hasToken) {
    tokens.push(current)
  }
  return tokens
}

function tryOrigin(candidate: string): string | undefined {
  const trimmed = candidate.trim()
  if (!/^https?:\/\//i.test(trimmed)) return undefined
  try {
    return new URL(trimmed).origin
  } catch {
    return undefined
  }
}

function parseHeaderLine(rawHeader: string): { name: string; value: string } | null {
  const colon = rawHeader.indexOf(':')
  if (colon <= 0) return null
  const name = rawHeader.slice(0, colon).trim()
  const value = rawHeader.slice(colon + 1).trim()
  if (!name || !/^[A-Za-z0-9-]+$/.test(name) || !value) return null
  return { name, value }
}

function summarizeCookies(cookieVal: string, origin?: string): ParsedCurlCredentials {
  const names = cookieVal
    .split(';')
    .map(part => part.split('=')[0]?.trim())
    .filter(Boolean)
  return {
    origin,
    authKind: 'cookie',
    secret: cookieVal,
    summary: `Extracted ${names.length} cookie${names.length === 1 ? '' : 's'} (${names.slice(0, 4).join(', ')}${names.length > 4 ? '…' : ''})${origin ? ` for ${origin}` : ''}.`,
  }
}

function isIgnoredHeader(name: string): boolean {
  const lower = name.toLowerCase()
  return IGNORED_BROWSER_HEADERS.has(lower) || lower.startsWith('sec-')
}

function pickCredentialsFromParsed(
  headers: ReadonlyArray<{ name: string; value: string }>,
  cookieParts: readonly string[],
  origin?: string,
): ParsedCurlCredentials | null {
  // 1. Authorization: Bearer <token>
  for (const h of headers) {
    if (h.name.toLowerCase() === 'authorization') {
      const bearer = /^bearer\s+(.+)$/i.exec(h.value)
      if (bearer?.[1]?.trim()) {
        return {
          origin,
          authKind: 'bearer',
          secret: bearer[1].trim(),
          summary: `Extracted Bearer token${origin ? ` for ${origin}` : ''} (masked in secret input).`,
        }
      }
    }
  }

  // 2. Cookie header(s) and/or -b / --cookie flags
  const allCookies: string[] = []
  for (const h of headers) {
    if (h.name.toLowerCase() === 'cookie' && h.value) {
      allCookies.push(h.value)
    }
  }
  for (const c of cookieParts) {
    const trimmed = c.trim()
    if (trimmed) allCookies.push(trimmed)
  }
  if (allCookies.length > 0) {
    const merged = allCookies.join('; ')
    return summarizeCookies(merged, origin)
  }

  // 3. Non-Bearer Authorization header (e.g. Token ..., Basic ..., ApiKey ...)
  for (const h of headers) {
    if (h.name.toLowerCase() === 'authorization' && h.value) {
      return {
        origin,
        authKind: 'header',
        headerName: 'Authorization',
        secret: h.value,
        summary: `Extracted Authorization header${origin ? ` for ${origin}` : ''}.`,
      }
    }
  }

  // 4. Custom auth headers (preferring well-known auth header names over arbitrary custom headers)
  const candidates = headers.filter(h => !isIgnoredHeader(h.name))
  const preferred = candidates.find(h => PREFERRED_AUTH_HEADER_PATTERN.test(h.name))
  const chosen = preferred ?? candidates[0]
  if (chosen) {
    return {
      origin,
      authKind: 'header',
      headerName: chosen.name,
      secret: chosen.value,
      summary: `Extracted ${chosen.name} header${origin ? ` for ${origin}` : ''}.`,
    }
  }

  return null
}

function parseCurlCommand(raw: string): ParsedCurlCredentials | null {
  const args = tokenizeShellArgs(raw)
  if (args.length === 0) return null
  const first = args[0]!.toLowerCase()
  if (first !== 'curl' && first !== 'curl.exe') return null

  const headers: Array<{ name: string; value: string }> = []
  const cookies: string[] = []
  let origin: string | undefined

  for (let i = 1; i < args.length; i += 1) {
    const arg = args[i]!

    if (arg === '--') {
      const next = args[i + 1]
      if (!origin && next) origin = tryOrigin(next)
      break
    }

    if (arg === '-H' || arg === '--header') {
      const val = args[i + 1]
      if (val !== undefined) {
        const parsed = parseHeaderLine(val)
        if (parsed) headers.push(parsed)
        i += 1
      }
      continue
    }
    if (arg.startsWith('--header=')) {
      const parsed = parseHeaderLine(arg.slice('--header='.length))
      if (parsed) headers.push(parsed)
      continue
    }
    if (arg.startsWith('-H') && arg.length > 2) {
      const parsed = parseHeaderLine(arg.slice(2))
      if (parsed) headers.push(parsed)
      continue
    }

    if (arg === '-b' || arg === '--cookie') {
      const val = args[i + 1]
      if (val !== undefined) {
        if (val.includes('=')) cookies.push(val.trim())
        i += 1
      }
      continue
    }
    if (arg.startsWith('--cookie=')) {
      const val = arg.slice('--cookie='.length).trim()
      if (val.includes('=')) cookies.push(val)
      continue
    }
    if (arg.startsWith('-b') && arg.length > 2) {
      const val = arg.slice(2).trim()
      if (val.includes('=')) cookies.push(val)
      continue
    }

    if (arg === '--url') {
      const val = args[i + 1]
      if (val !== undefined) {
        if (!origin) origin = tryOrigin(val)
        i += 1
      }
      continue
    }
    if (arg.startsWith('--url=')) {
      if (!origin) origin = tryOrigin(arg.slice('--url='.length))
      continue
    }

    if (CURL_OPTIONS_WITH_ARG.has(arg)) {
      i += 1
      continue
    }

    if (arg.startsWith('-')) {
      continue
    }

    if (!origin) {
      origin = tryOrigin(arg)
    }
  }

  return pickCredentialsFromParsed(headers, cookies, origin)
}

/**
 * Client-side parser for pasted `curl ...` commands or raw `Cookie:` / `Authorization:` headers.
 * Never logs secrets; returns structured fields so the caller can populate the masked password input.
 */
export function parseCurlOrHeader(raw: string): ParsedCurlCredentials | null {
  const input = raw.trim()
  if (!input) return null

  // 1. Structured shell tokenizer for cURL commands (Chrome/Firefox DevTools, bash/zsh/cmd).
  if (/^curl(?:\.exe)?(?:\s|$)/i.test(input)) {
    return parseCurlCommand(input)
  }

  // 2. Raw multi-line HTTP headers (e.g. copied from DevTools Request Headers)
  let origin: string | undefined
  const urlMatch = input.match(/https?:\/\/[a-z0-9.-]+(?::\d+)?/i)
  if (urlMatch) {
    origin = tryOrigin(urlMatch[0])
  }

  const lines = input.split(/\r?\n/).map(line => line.trim()).filter(Boolean)
  const rawHeaders: Array<{ name: string; value: string }> = []
  for (const line of lines) {
    const parsed = parseHeaderLine(line)
    if (parsed) rawHeaders.push(parsed)
  }
  if (rawHeaders.length > 0) {
    const picked = pickCredentialsFromParsed(rawHeaders, [], origin)
    if (picked) return picked
  }

  // 3. Fallback: raw cookie pairs like "__session=abc; __client_uat=123"
  if (input.includes('=')) {
    const names = input
      .split(';')
      .map(part => part.split('=')[0]?.trim())
      .filter(Boolean)
    return {
      origin,
      authKind: 'cookie',
      secret: input,
      summary: `Parsed ${names.length} raw cookie pair${names.length === 1 ? '' : 's'} (${names.slice(0, 4).join(', ')}).`,
    }
  }

  return null
}

/**
 * Formats a broker exchange as a sanitized, copy-ready cURL command.
 */
export function formatExchangeAsCurl(ex: {
  method: string
  origin: string
  pathAndQuery: string
  reqHeaders?: Record<string, string>
  personaHandle?: string | null
}): string {
  const lines = [`curl -i -X ${ex.method} '${ex.origin}${ex.pathAndQuery}'`]
  const entries = Object.entries(ex.reqHeaders ?? {})
  for (const [key, value] of entries) {
    if (key.toLowerCase() === 'host') continue
    lines.push(`  -H '${key}: ${String(value).replace(/'/g, "'\\''")}'`)
  }
  if (ex.personaHandle && !entries.some(([k]) => /^(cookie|authorization)$/i.test(k))) {
    lines.push(`  -H 'Cookie: [persona:${ex.personaHandle}:secret]'`)
  }
  return lines.join(' \\\n')
}
