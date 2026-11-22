// Thin API client. Loads the runtime route map from /app-config.json so the SPA never hardcodes
// server paths (the api prefix and resource nouns vary per deployment).
let config = null

export async function loadConfig() {
  if (config) return config
  const res = await fetch('/app-config.json', { credentials: 'same-origin' })
  config = await res.json()
  return config
}

export function routePath(key, pathParams = {}, query = {}) {
  const r = config.routes[key]
  if (!r) throw new Error(`unknown route ${key}`)
  let path = r.path
  for (const [name, value] of Object.entries(pathParams)) {
    path = path.replace(`:${name}`, encodeURIComponent(value))
  }
  const qs = Object.entries(query)
    .map(([k, v]) => `${encodeURIComponent(k)}=${encodeURIComponent(v)}`)
    .join('&')
  return qs ? `${path}?${qs}` : path
}

let csrfToken = null
export function setCsrf(token) { csrfToken = token }

export async function call(key, { pathParams, query, method, body } = {}) {
  const r = config.routes[key]
  const headers = {}
  let payload
  if (body !== undefined) { headers['content-type'] = 'application/json'; payload = JSON.stringify(body) }
  if (csrfToken) headers['x-csrf-token'] = csrfToken
  const res = await fetch(routePath(key, pathParams, query), {
    method: method || (r ? r.method : 'GET'),
    headers,
    credentials: 'same-origin',
    body: payload,
  })
  const text = await res.text()
  let json = null
  try { json = JSON.parse(text) } catch { json = null }
  return { status: res.status, json, text }
}
