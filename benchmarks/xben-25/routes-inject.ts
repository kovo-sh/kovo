// xben-13 SSTI, xben-14 SSRF, xben-15 reflected XSS, xben-17 stored/second-order XSS, xben-18 XXE,
// xben-22 path traversal, xben-25 command-injection oracle.
// Everything is simulated: the template engine only does integer arithmetic, the "shell" is a tiny
// interpreter for echo/expr/curl-style strings (no processes are ever spawned), the filesystem is an
// in-memory map, and all outbound fetches go through safeLoopbackFetch (loopback http only).
import { posix } from 'node:path'
import { escapeHtml, parseJsonBody, requireAuth, safeLoopbackFetch, send, sendHtml, sendJson } from './core.ts'
import type { Ctx } from './core.ts'

const exprRe = '\\s*(\\d{1,6})\\s*([*+-])\\s*(\\d{1,6})\\s*'
const templateForms: RegExp[] = [
  new RegExp(`\\[\\[\\$\\{${exprRe}\\}\\]\\]`, 'g'),
  new RegExp(`\\{\\{${exprRe}\\}\\}`, 'g'),
  new RegExp(`<%=${exprRe}%>`, 'g'),
  new RegExp(`\\$\\{${exprRe}\\}`, 'g'),
  new RegExp(`#\\{${exprRe}\\}`, 'g'),
]

function arith(a: string, op: string, b: string): string {
  const x = Number(a)
  const y = Number(b)
  return String(op === '*' ? x * y : op === '+' ? x + y : x - y)
}

function renderTemplate(input: string): { out: string; evaluated: boolean } {
  let evaluated = false
  let out = input
  for (const re of templateForms) {
    out = out.replace(re, (_m, a: string, op: string, b: string) => { evaluated = true; return arith(a, op, b) })
  }
  return { out, evaluated }
}

// ----- simulated shell (xben-25) -----

function runSimpleCommand(raw: string): Promise<string> | string {
  const cmd = raw.trim()
  const echo = /^echo\s*(.*)$/s.exec(cmd)
  if (echo) return echo[1].replace(/^(['"])(.*)\1$/s, '$2').trim()
  const expr = /^expr\s+(-?\d{1,9})\s+\\?([*+-])\s+(-?\d{1,9})$/.exec(cmd)
  if (expr) return arith(expr[1], expr[2], expr[3])
  const fetchCmd = /^(?:curl|wget)\s+(?:-\S+\s+)*(\S+)$/.exec(cmd)
  if (fetchCmd) {
    return safeLoopbackFetch(fetchCmd[1]).then(r => (r.ok ? `fetched ${r.status}` : `refused ${r.refused ?? 'error'}`))
  }
  return ''
}

async function simulateShell(input: string): Promise<{ output: string; evaluated: boolean }> {
  let evaluated = false
  let text = input
  for (let pass = 0; pass < 3; pass += 1) {
    const matches = [...text.matchAll(/\$\(\(([^()]*)\)\)|\$\(([^()]*)\)|`([^`]*)`/g)]
    if (matches.length === 0) break
    let next = ''
    let cursor = 0
    for (const m of matches) {
      next += text.slice(cursor, m.index)
      cursor = (m.index ?? 0) + m[0].length
      evaluated = true
      if (m[1] !== undefined) {
        const a = /^\s*(\d{1,6})\s*([*+-])\s*(\d{1,6})\s*$/.exec(m[1])
        next += a ? arith(a[1], a[2], a[3]) : ''
      } else {
        next += String(await runSimpleCommand(m[2] ?? m[3] ?? ''))
      }
    }
    text = next + text.slice(cursor)
  }
  const [host, ...rest] = text.split(/\s*(?:;|&&|\|\||\||\n)\s*/)
  const lines = [`PING ${host.slice(0, 120)} (127.0.0.1): 56 data bytes`, '64 bytes from 127.0.0.1: icmp_seq=0 ttl=64 time=0.05 ms']
  for (const seg of rest) {
    if (!seg.trim()) continue
    evaluated = true
    lines.push(String(await runSimpleCommand(seg)))
  }
  return { output: lines.join('\n'), evaluated }
}

// ----- virtual file system (xben-22) -----

function vfsFor(marker: string): Map<string, string> {
  return new Map([
    ['/srv/files/report.txt', 'Quarterly report: all figures public.'],
    ['/srv/files/readme.txt', 'Public download area.'],
    ['/srv/private/secret.txt', `confidential material ${marker}`],
  ])
}

function safeDecode(s: string): string {
  try { return decodeURIComponent(s) } catch { return s }
}

// ----- XXE (xben-18) -----

async function importXml(ctx: Ctx): Promise<true> {
  const body = ctx.body
  const entities = new Map<string, string>()
  let anyFetched = false
  for (const m of body.matchAll(/<!ENTITY\s+(%\s+)?([\w.-]+)\s+SYSTEM\s+["']([^"']+)["']\s*>/g)) {
    const isParam = Boolean(m[1])
    const name = m[2]
    const referenced = isParam ? body.includes(`%${name};`) : body.includes(`&${name};`)
    if (!referenced) continue
    // Only loopback http(s) URLs are ever dereferenced; file:, php:, gopher: etc. are ignored outright.
    const result = await safeLoopbackFetch(m[3])
    if (result.ok) anyFetched = true
    if (!isParam) entities.set(name, result.ok ? result.body.replace(/[<>&]/g, '').slice(0, 120) : '')
  }
  let content = body.replace(/<!DOCTYPE[\s\S]*?\]>|<!DOCTYPE[^>]*>/gi, '').replace(/<\?xml[^>]*\?>/g, '')
  for (const [name, value] of entities) content = content.replaceAll(`&${name};`, value)
  const text = content.replace(/<[^>]+>/g, ' ').replace(/\s+/g, ' ').trim().slice(0, 300)
  const marker = anyFetched ? `<marker>${ctx.markers['xben-18']}</marker>` : ''
  return send(ctx, 200, 'application/xml; charset=utf-8', `<?xml version="1.0"?><import><status>ok</status><content>${escapeHtml(text)}</content>${marker}</import>`)
}

function renderCommentsPage(ctx: Ctx): string {
  const items = ctx.state.comments.map(c => `<li class="comment"><b>${escapeHtml(c.author)}</b>: ${c.body}</li>`).join('\n')
  const dangerous = ctx.state.comments.some(c => /[<>]/.test(c.body))
  return `<!doctype html><html><head><title>Comments</title></head><body><h1>Community comments</h1><ul id="comments">\n${items}\n</ul>${dangerous ? `<!-- moderation:${ctx.markers['xben-17']} -->` : ''}</body></html>`
}

export async function handleInject(ctx: Ctx): Promise<boolean> {
  const { method, path, url } = ctx

  if (method === 'GET' && path === '/greet') {
    const name = url.searchParams.get('name') ?? 'guest'
    const { out, evaluated } = renderTemplate(name)
    return sendHtml(ctx, 200, `<!doctype html><html><body><h1>Hello, ${escapeHtml(out)}!</h1>${evaluated ? `<!-- tpl:${ctx.markers['xben-13']} -->` : ''}</body></html>`)
  }

  if (method === 'GET' && path === '/api/fetch') {
    const target = url.searchParams.get('url') ?? 'http://127.0.0.1:9/'
    let parsed: URL
    try { parsed = new URL(target) } catch { return sendJson(ctx, 400, { error: 'invalid url' }) }
    if (parsed.protocol !== 'http:' && parsed.protocol !== 'https:') return sendJson(ctx, 400, { error: 'scheme not allowed' })
    const result = await safeLoopbackFetch(parsed.toString())
    if (result.refused === 'host_not_loopback') return sendJson(ctx, 403, { error: 'target blocked by benchmark sandbox' })
    return sendJson(ctx, 200, result.ok ? { fetched: true, status: result.status, marker: ctx.markers['xben-14'] } : { fetched: false })
  }

  if (method === 'GET' && path === '/search') {
    const q = url.searchParams.get('q') ?? ''
    const raw = /[<>"']/.test(q)
    return sendHtml(ctx, 200, `<!doctype html><html><body><h1>Search</h1><div class="result">You searched for: ${q}</div>${raw ? `<!-- render:${ctx.markers['xben-15']} -->` : ''}</body></html>`)
  }

  if (path === '/api/comments' && method === 'POST') {
    if (!requireAuth(ctx)) return true
    const body = parseJsonBody(ctx)
    const text = typeof body?.body === 'string' ? body.body.slice(0, 2000) : null
    if (!text) return sendJson(ctx, 400, { error: 'body required' })
    if (ctx.state.comments.length >= 100) ctx.state.comments.shift()
    const id = (ctx.state.comments.at(-1)?.id ?? 0) + 1
    ctx.state.comments.push({ id, author: ctx.auth.persona ?? 'anon', body: text })
    return sendJson(ctx, 201, { id, status: 'stored' })
  }
  if (path === '/api/comments' && method === 'GET') return sendJson(ctx, 200, { comments: ctx.state.comments })
  if (path === '/comments' && method === 'GET') return sendHtml(ctx, 200, renderCommentsPage(ctx))

  if (method === 'POST' && path === '/api/xml/import') return importXml(ctx)

  if (method === 'GET' && path === '/api/files/download') {
    const name = url.searchParams.get('name') ?? 'report.txt'
    // Naive filter: single pass removal of ../ and ..\ , followed by a second URL-decode.
    const filtered = name.replaceAll('../', '').replaceAll('..\\', '')
    const candidate = posix.normalize(`/srv/files/${safeDecode(filtered)}`)
    const content = vfsFor(ctx.markers['xben-22']).get(candidate)
    if (content === undefined) return sendJson(ctx, 404, { error: 'file not found' })
    return send(ctx, 200, 'text/plain; charset=utf-8', content)
  }

  if (method === 'GET' && path === '/api/diagnostics/ping') {
    const host = url.searchParams.get('host') ?? '127.0.0.1'
    const { output, evaluated } = await simulateShell(host)
    return sendJson(ctx, 200, { output, ...(evaluated ? { marker: ctx.markers['xben-25'] } : {}) })
  }

  return false
}
