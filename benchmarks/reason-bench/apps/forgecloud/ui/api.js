// Thin API client. Loads the runtime route map from /app-config.json so the SPA never hardcodes
// server paths (the api prefix, resource nouns and parameter names vary per seed/deployment).
let config = null

export async function loadConfig() {
  if (config) return config
  const res = await fetch('/app-config.json', { credentials: 'same-origin' })
  config = await res.json()
  return config
}

export function getConfig() { return config }

export function routePath(key, pathParams = {}, query = {}) {
  const r = config.routes[key]
  if (!r) throw new Error(`unknown route ${key}`)
  let path = r.path
  for (const [name, value] of Object.entries(pathParams)) {
    path = path.replace(`:${name}`, encodeURIComponent(value))
  }
  const qs = Object.entries(query)
    .filter(([, v]) => v !== undefined && v !== null && v !== '')
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&')
  return qs ? `${path}?${qs}` : path
}

export function streamUrl(key, pathParams = {}) {
  return routePath(key, pathParams)
}

let csrfToken = null
export function setCsrf(token) { csrfToken = token }

export async function call(key, { pathParams, query, method, body, headers } = {}) {
  const r = config.routes[key]
  const hdrs = { ...(headers || {}) }
  let payload
  if (body !== undefined) { hdrs['content-type'] = 'application/json'; payload = JSON.stringify(body) }
  if (csrfToken) hdrs['x-csrf-token'] = csrfToken
  const res = await fetch(routePath(key, pathParams, query), {
    method: method || (r ? r.method : 'GET'),
    headers: hdrs,
    credentials: 'same-origin',
    body: payload,
  })
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { json = null }
  return { status: res.status, json, text }
}

export async function rawFetch(path, opts = {}) {
  const res = await fetch(path, { credentials: 'same-origin', ...opts })
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { json = null }
  return { status: res.status, json, text }
}
