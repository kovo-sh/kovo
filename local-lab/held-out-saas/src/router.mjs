// Tiny express-style router (`router.get('/path/:id', handler)`), pure node stdlib.

export function createRouter() {
  const routes = []

  const add = method => (pattern, handler) => {
    const keys = []
    const source = pattern
      .replace(/[.+?^${}()|[\]\\]/g, '\\$&')
      .replace(/:([A-Za-z_]\w*)/g, (_m, key) => {
        keys.push(key)
        return '([^/]+)'
      })
      .replace(/\*$/, () => {
        keys.push('splat')
        return '(.*)'
      })
    routes.push({ method, pattern, re: new RegExp(`^${source}/?$`), keys, handler })
  }

  return {
    get: add('GET'),
    post: add('POST'),
    put: add('PUT'),
    patch: add('PATCH'),
    delete: add('DELETE'),
    routes,
    match(method, pathname) {
      let pathMatched = false
      for (const route of routes) {
        const m = route.re.exec(pathname)
        if (!m) continue
        pathMatched = true
        if (route.method !== method && !(method === 'HEAD' && route.method === 'GET')) continue
        const params = {}
        route.keys.forEach((key, i) => {
          try { params[key] = decodeURIComponent(m[i + 1]) } catch { params[key] = m[i + 1] }
        })
        return { route, params }
      }
      return pathMatched ? { methodNotAllowed: true } : null
    },
  }
}
