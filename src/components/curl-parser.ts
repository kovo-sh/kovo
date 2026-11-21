export interface ParsedCurlCredentials {
  origin?: string
  authKind: 'cookie' | 'bearer' | 'header'
  headerName?: string
  secret: string
  summary: string
}

/**
 * Client-side parser for pasted `curl ...` commands or raw `Cookie:` / `Authorization:` headers.
 * Never logs secrets; returns structured fields so the caller can populate the masked password input.
 */
export function parseCurlOrHeader(raw: string): ParsedCurlCredentials | null {
  const input = raw.trim()
  if (!input) return null

  let origin: string | undefined
  const urlMatch = input.match(/https?:\/\/[a-z0-9.-]+(?::\d+)?/i)
  if (urlMatch) {
    try {
      origin = new URL(urlMatch[0]).origin
    } catch {
      origin = undefined
    }
  }

  // 1. Check Authorization: Bearer <token>
  const bearerMatch = input.match(/(?:^|['"\s])authorization\s*:\s*bearer\s+([^\s'"]+)/i)
  if (bearerMatch?.[1]) {
    return {
      origin,
      authKind: 'bearer',
      secret: bearerMatch[1].trim(),
      summary: `Extracted Bearer token${origin ? ` for ${origin}` : ''} (masked in secret input).`,
    }
  }

  // 2. Check -b / --cookie flag or Cookie: header
  const cookieHeaderMatch =
    input.match(/-H\s+['"]cookie\s*:\s*([^'"]+)['"]/i) ??
    input.match(/(?:--cookie|-b)\s+['"]([^'"]+)['"]/i) ??
    input.match(/^cookie\s*:\s*(.+)$/im)

  if (cookieHeaderMatch?.[1]) {
    const cookieVal = cookieHeaderMatch[1].trim()
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

  // 3. Check custom auth header like X-Api-Key: ...
  const customHeaderMatch =
    input.match(/-H\s+['"]([A-Za-z0-9-]+)\s*:\s*([^'"]+)['"]/i) ??
    input.match(/^([A-Za-z0-9-]+)\s*:\s*(.+)$/m)
  if (customHeaderMatch?.[1] && customHeaderMatch[2]) {
    const hName = customHeaderMatch[1].trim()
    const hVal = customHeaderMatch[2].trim()
    if (!/^(host|user-agent|accept|content-type|accept-language|referer|origin)$/i.test(hName)) {
      if (hName.toLowerCase() === 'authorization' && !/^bearer\s+/i.test(hVal)) {
        return {
          origin,
          authKind: 'header',
          headerName: 'Authorization',
          secret: hVal,
          summary: `Extracted Authorization header${origin ? ` for ${origin}` : ''}.`,
        }
      }
      return {
        origin,
        authKind: 'header',
        headerName: hName,
        secret: hVal,
        summary: `Extracted ${hName} header${origin ? ` for ${origin}` : ''}.`,
      }
    }
  }

  // 4. Fallback: raw cookie pairs like "__session=abc; __client_uat=123"
  if (input.includes('=') && !input.startsWith('curl ')) {
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
