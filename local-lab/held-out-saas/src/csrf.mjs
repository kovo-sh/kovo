import { randomBytes } from 'node:crypto'
import { parseCookies } from './http-util.mjs'

/** Issues a double-submit CSRF token (cookie + hidden form field) and registers it server-side. */
export function issueCsrf(ctx, res) {
  const token = randomBytes(16).toString('hex')
  if (ctx.s.csrfTokens.size > 500) ctx.s.csrfTokens.clear()
  ctx.s.csrfTokens.add(token)
  res.setHeader('set-cookie', `csrf_token=${token}; Path=/; SameSite=Lax`)
  return token
}

export function csrfValid(ctx, req, submitted) {
  const cookieToken = parseCookies(req.headers.cookie ?? '').csrf_token
  const sent = submitted || req.headers['x-csrf-token']
  return Boolean(cookieToken && sent && cookieToken === sent && ctx.s.csrfTokens.has(cookieToken))
}
