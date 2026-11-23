// Cookie parsing and serialization for the benchmark HTTP layer. No deps; node built-ins only.

export interface CookieOptions {
  httpOnly?: boolean
  sameSite?: 'Strict' | 'Lax' | 'None'
  secure?: boolean
  path?: string
  maxAge?: number // seconds
  expires?: Date
}

/** Parse a `Cookie:` header into a flat name->value map. Values are URL-decoded best-effort. */
export function parseCookies(header: string | undefined | null): Record<string, string> {
  const out: Record<string, string> = {}
  if (!header) return out
  for (const part of header.split(';')) {
    const eq = part.indexOf('=')
    if (eq < 0) continue
    const name = part.slice(0, eq).trim()
    if (!name) continue
    let value = part.slice(eq + 1).trim()
    if (value.startsWith('"') && value.endsWith('"') && value.length >= 2) {
      value = value.slice(1, -1)
    }
    try {
      value = decodeURIComponent(value)
    } catch {
      // keep raw value if it is not valid percent-encoding
    }
    out[name] = value
  }
  return out
}

/** Serialize a single Set-Cookie header value. Name/value are URL-encoded. */
export function serializeCookie(name: string, value: string, opts: CookieOptions = {}): string {
  const segs = [`${name}=${encodeURIComponent(value)}`]
  segs.push(`Path=${opts.path ?? '/'}`)
  if (opts.maxAge !== undefined) segs.push(`Max-Age=${Math.floor(opts.maxAge)}`)
  if (opts.expires) segs.push(`Expires=${opts.expires.toUTCString()}`)
  if (opts.httpOnly) segs.push('HttpOnly')
  if (opts.secure) segs.push('Secure')
  if (opts.sameSite) segs.push(`SameSite=${opts.sameSite}`)
  return segs.join('; ')
}

/** Build a Set-Cookie value that immediately expires (clears) a cookie. */
export function clearCookie(name: string, opts: CookieOptions = {}): string {
  return serializeCookie(name, '', { ...opts, maxAge: 0, expires: new Date(0) })
}
