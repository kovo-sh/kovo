import { LOOPBACK_HOSTS } from './config.mjs'

export const delay = ms => new Promise(resolve => setTimeout(resolve, ms))

export function escapeHtml(value) {
  return String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;')
}

export function httpError(status, message) {
  const err = new Error(message)
  err.status = status
  return err
}

function finish(res, status, headers, body) {
  const out = { 'content-length': String(Buffer.byteLength(body)), ...headers }
  if (typeof res.cacheCapture === 'function') res.cacheCapture(status, out, body)
  res.writeHead(status, out)
  res.end(body)
}

export function sendJson(res, status, obj, headers = {}) {
  finish(res, status, { 'content-type': 'application/json; charset=utf-8', ...headers }, JSON.stringify(obj))
}

export function sendHtml(res, status, html, headers = {}) {
  finish(res, status, { 'content-type': 'text/html; charset=utf-8', ...headers }, html)
}

export function sendText(res, status, text, type = 'text/plain; charset=utf-8', headers = {}) {
  finish(res, status, { 'content-type': type, ...headers }, text)
}

export async function readBody(req, limit = 262_144) {
  const chunks = []
  let size = 0
  for await (const chunk of req) {
    size += chunk.length
    if (size > limit) throw httpError(413, 'payload too large')
    chunks.push(chunk)
  }
  return Buffer.concat(chunks).toString('utf8')
}

export function parseCookies(header = '') {
  const out = {}
  for (const part of String(header).split(';')) {
    const idx = part.indexOf('=')
    if (idx > 0) out[part.slice(0, idx).trim()] = part.slice(idx + 1).trim()
  }
  return out
}

export function isLoopbackUrl(raw) {
  try {
    const u = new URL(raw)
    return (u.protocol === 'http:' || u.protocol === 'https:') && LOOPBACK_HOSTS.has(u.hostname)
  } catch {
    return false
  }
}

/**
 * The ONLY outbound HTTP primitive in the lab. Anything that is not a loopback / lab-internal origin
 * is refused before a socket is opened (sandbox guarantee for every SSRF / XXE / JKU style sink).
 */
export async function fetchLoopback(raw, { timeoutMs = 2000, maxBytes = 4096, headers = {} } = {}) {
  if (!isLoopbackUrl(raw)) {
    return { ok: false, blocked: true, status: 0, body: '', error: 'egress blocked: lab sandbox only permits loopback/internal origins' }
  }
  try {
    const r = await fetch(raw, { redirect: 'manual', headers, signal: AbortSignal.timeout(timeoutMs) })
    const text = (await r.text()).slice(0, maxBytes)
    return { ok: r.ok, blocked: false, status: r.status, body: text }
  } catch (err) {
    return { ok: false, blocked: false, status: 0, body: '', error: String(err?.message ?? err) }
  }
}
