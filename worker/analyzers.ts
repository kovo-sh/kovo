export type AnalyzerName =
  | 'js-harvest'
  | 'jwt-inspect'
  | 'graphql-parse'
  | 'openapi-parse'
  | 'diff-response'
  | 'dns-takeover'
  | 'secret-scan'
  | 'tech-fingerprint'

function uniq(items: string[], limit = 200): string[] {
  return [...new Set(items.filter(Boolean))].slice(0, limit)
}

export function jsHarvest(content: string, sourceName = ''): Record<string, unknown> {
  const apiPaths = uniq([
    ...[...content.matchAll(/["'`](\/(?:api|v[1-9]|graphql|trpc|auth|oauth|sso|admin|internal|debug|upload|webhook|billing|account|user|session|_next\/data)[a-zA-Z0-9_./:${}-]{0,140})["'`]/g)].map(m => m[1]),
    ...[...content.matchAll(/(?:fetch|axios\.(?:get|post|put|patch|delete)|url\s*:\s*)\(\s*["'`](\/[a-zA-Z0-9_./:${}?=&-]{1,160})["'`]/g)].map(m => m[1]),
  ], 150)

  const scriptChunks = uniq([
    ...[...content.matchAll(/["'`](\/_next\/static\/[a-zA-Z0-9_./-]+\.(?:js|mjs|json))["'`]/g)].map(m => m[1]),
    ...[...content.matchAll(/src=["'](\/[^"']+\.(?:js|mjs)(?:\?[^"']*)?)["']/gi)].map(m => m[1]),
  ], 120)

  const sourceMaps = uniq([
    ...[...content.matchAll(/\/\/[#@]\s*sourceMappingURL=([^\s'"]+)/g)].map(m => m[1]),
  ], 40)

  const externalUrls = uniq([
    ...[...content.matchAll(/(?:https?|wss?):\/\/[a-zA-Z0-9.-]+(?::\d+)?(?:\/[a-zA-Z0-9_./?=&%+-]{0,120})?/g)].map(m => m[0]),
  ].filter(u => !/w3\.org|schema\.org|googleapis\.com\/css|fonts\.gstatic|mozilla\.org/.test(u)), 120)

  const domSinks = uniq([
    ...(content.includes('postMessage') ? ['postMessage'] : []),
    ...(content.includes("addEventListener('message'") || content.includes('addEventListener("message"') ? ['message-listener'] : []),
    ...(content.includes('dangerouslySetInnerHTML') ? ['dangerouslySetInnerHTML'] : []),
    ...(/\binnerHTML\b/.test(content) ? ['innerHTML'] : []),
    ...(/\beval\s*\(/.test(content) ? ['eval'] : []),
    ...(/\bdocument\.domain\b/.test(content) ? ['document.domain'] : []),
    ...(/window\.open\s*\(/.test(content) ? ['window.open'] : []),
  ], 20)

  const nextDataMatch = content.match(/<script[^>]+id=["']__NEXT_DATA__["'][^>]*>([\s\S]*?)<\/script>/i)
  let nextMeta: Record<string, unknown> | undefined
  if (nextDataMatch) {
    try {
      const parsed = JSON.parse(nextDataMatch[1]) as Record<string, unknown>
      nextMeta = {
        page: parsed.page,
        buildId: parsed.buildId,
        runtimeConfigKeys: parsed.runtimeConfig && typeof parsed.runtimeConfig === 'object' ? Object.keys(parsed.runtimeConfig) : [],
        propKeys: parsed.props && typeof parsed.props === 'object' ? Object.keys(parsed.props) : [],
      }
    } catch {
      nextMeta = { parseError: true }
    }
  }

  const secretFindings = secretScan(content, sourceName)
  return {
    sourceName,
    bytes: content.length,
    apiPaths,
    scriptChunks,
    sourceMaps,
    externalUrls,
    domSinks,
    ...(nextMeta ? { nextMeta } : {}),
    secretMatches: secretFindings.matches,
  }
}

export function secretScan(content: string, sourceName = ''): { sourceName: string; matches: Array<{ kind: string; preview: string; index: number }> } {
  const rules: Array<{ kind: string; regex: RegExp }> = [
    { kind: 'aws-access-key', regex: /\bAKIA[0-9A-Z]{16}\b/g },
    { kind: 'stripe-live-key', regex: /\bsk_live_[0-9a-zA-Z]{16,}\b/g },
    { kind: 'stripe-pub-key', regex: /\bpk_(?:live|test)_[0-9a-zA-Z]{16,}\b/g },
    { kind: 'clerk-pub-key', regex: /\bpk_(?:live|test)_[A-Za-z0-9+/=]{20,}\b/g },
    { kind: 'supabase-url', regex: /https:\/\/[a-z0-9]{12,32}\.supabase\.co\b/g },
    { kind: 'jwt-literal', regex: /\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{8,}\b/g },
    { kind: 'private-key', regex: /-----BEGIN [A-Z ]*PRIVATE KEY-----/g },
    { kind: 'google-api-key', regex: /\bAIza[0-9A-Za-z_-]{35}\b/g },
    { kind: 'slack-webhook', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Z0-9/]+/g },
    { kind: 'generic-secret-var', regex: /\b(?:SERVICE_ROLE_KEY|SUPABASE_SERVICE_ROLE|OPENAI_API_KEY|ANTHROPIC_API_KEY|DATABASE_URL|POSTGRES_URL|JWT_SECRET|NEXTAUTH_SECRET)\s*[:=]\s*["'`][^"'`]{6,120}["'`]/gi },
  ]
  const matches: Array<{ kind: string; preview: string; index: number }> = []
  for (const rule of rules) {
    for (const match of content.matchAll(rule.regex)) {
      if (matches.length >= 60) break
      const raw = match[0]
      // Mask middle of secret-like strings so raw credentials never propagate into summaries.
      const preview = raw.length > 16 && !rule.kind.endsWith('-url')
        ? raw.slice(0, 8) + '…[masked:' + raw.length + ']…' + raw.slice(-4)
        : raw.slice(0, 120)
      matches.push({ kind: rule.kind, preview, index: match.index ?? 0 })
    }
  }
  return { sourceName, matches }
}

export function jwtInspect(token: string): Record<string, unknown> {
  const parts = token.trim().split('.')
  if (parts.length < 2 || parts.length > 3) return { valid: false, error: 'Not a JWT structure.' }
  const decode = (part: string) => JSON.parse(Buffer.from(part.replace(/-/g, '+').replace(/_/g, '/'), 'base64').toString('utf8')) as Record<string, unknown>
  try {
    const header = decode(parts[0])
    const payload = decode(parts[1])
    const warnings: string[] = []
    if (String(header.alg ?? '').toLowerCase() === 'none') warnings.push('alg=none accepted/present')
    if (header.jku || header.x5u) warnings.push('External key URL header (jku/x5u) present')
    if (header.kid) warnings.push('kid header present (check for path traversal/SQLi in key lookup)')
    if (payload.exp === undefined) warnings.push('Missing exp claim')
    if (payload.aud === undefined) warnings.push('Missing aud claim')
    if (String(payload.role ?? '').includes('service_role') || payload.role === 'admin') {
      warnings.push(`Privileged role claim detected: ${String(payload.role)}`)
    }
    return {
      valid: true,
      header,
      claimKeys: Object.keys(payload),
      safeClaims: {
        iss: payload.iss, sub: payload.sub ? '[present]' : undefined, aud: payload.aud,
        role: payload.role, exp: payload.exp, iat: payload.iat,
      },
      hasSignature: Boolean(parts[2] && parts[2].length > 0),
      warnings,
    }
  } catch {
    return { valid: false, error: 'Could not base64url-decode JWT JSON segments.' }
  }
}

export function graphqlParse(content: string): Record<string, unknown> {
  try {
    const parsed = JSON.parse(content) as { data?: { __schema?: { queryType?: { name?: string }; mutationType?: { name?: string }; types?: Array<{ name: string; kind: string; fields?: Array<{ name: string }> }> } } }
    const schema = parsed.data?.__schema
    if (schema?.types) {
      const queries = schema.types.find(t => t.name === schema.queryType?.name)?.fields?.map(f => f.name) ?? []
      const mutations = schema.types.find(t => t.name === schema.mutationType?.name)?.fields?.map(f => f.name) ?? []
      const userTypes = schema.types.filter(t => !t.name.startsWith('__') && t.kind === 'OBJECT').map(t => ({
        name: t.name, fields: (t.fields ?? []).map(f => f.name).slice(0, 30),
      })).slice(0, 60)
      return { introspectionEnabled: true, queries: queries.slice(0, 100), mutations: mutations.slice(0, 100), userTypes }
    }
  } catch {
    // Fall back to regex extraction from JS bundles.
  }
  const operations = uniq([
    ...[...content.matchAll(/\b(?:query|mutation|subscription)\s+([A-Za-z0-9_]{2,64})\b/g)].map(m => `${m[0]}`),
  ], 100)
  return { introspectionEnabled: false, operations }
}

export function openapiParse(content: string): Record<string, unknown> {
  try {
    const doc = JSON.parse(content) as {
      openapi?: string; swagger?: string; info?: { title?: string; version?: string }
      paths?: Record<string, Record<string, { summary?: string; security?: unknown[]; parameters?: Array<{ name: string; in: string }> }>>
    }
    const endpoints: Array<{ method: string; path: string; summary?: string; unauthenticated?: boolean; params: string[] }> = []
    for (const [path, methods] of Object.entries(doc.paths ?? {})) {
      for (const [method, op] of Object.entries(methods ?? {})) {
        if (!['get', 'post', 'put', 'patch', 'delete', 'head', 'options'].includes(method.toLowerCase())) continue
        endpoints.push({
          method: method.toUpperCase(),
          path,
          summary: op?.summary?.slice(0, 100),
          unauthenticated: Array.isArray(op?.security) && op.security.length === 0,
          params: (op?.parameters ?? []).map(p => `${p.in}:${p.name}`).slice(0, 20),
        })
      }
    }
    return { specVersion: doc.openapi ?? doc.swagger ?? 'unknown', title: doc.info?.title, endpointCount: endpoints.length, endpoints: endpoints.slice(0, 200) }
  } catch {
    return { error: 'OpenAPI input must be valid JSON.' }
  }
}

export function diffResponse(control: { status?: number; body?: string; mediaType?: string },
  probe: { status?: number; body?: string; mediaType?: string }): Record<string, unknown> {
  const cBody = control.body ?? ''
  const pBody = probe.body ?? ''
  const tokenize = (s: string) => new Set(s.toLowerCase().replace(/[^a-z0-9]+/g, ' ').trim().split(/\s+/).filter(t => t.length > 2).slice(0, 1500))
  const a = tokenize(cBody)
  const b = tokenize(pBody)
  let intersect = 0
  for (const token of a) if (b.has(token)) intersect += 1
  const union = a.size + b.size - intersect
  const jaccard = union === 0 ? 1 : Number((intersect / union).toFixed(4))
  const likelySpaCatchall = control.status === 200 && probe.status === 200 &&
    (control.mediaType ?? '').includes('html') && (probe.mediaType ?? '').includes('html') && jaccard >= 0.85
  return {
    statusChanged: control.status !== probe.status,
    controlStatus: control.status,
    probeStatus: probe.status,
    mediaTypeChanged: control.mediaType !== probe.mediaType,
    lengthDelta: pBody.length - cBody.length,
    tokenSimilarity: jaccard,
    likelySpaCatchall,
  }
}

const takeoverSignatures: Array<{ provider: string; cname: RegExp; body: RegExp }> = [
  { provider: 'GitHub Pages', cname: /\.github\.io\.?$/i, body: /There isn't a GitHub Pages site here/i },
  { provider: 'Vercel', cname: /\.(?:vercel-dns\.com|now\.sh)\.?$/i, body: /DEPLOYMENT_NOT_FOUND|The deployment could not be found on Vercel/i },
  { provider: 'Netlify', cname: /\.netlify\.(?:app|com)\.?$/i, body: /Not Found - Request ID:/i },
  { provider: 'AWS S3', cname: /\.s3(?:[.-][a-z0-9-]+)?\.amazonaws\.com\.?$/i, body: /NoSuchBucket|The specified bucket does not exist/i },
  { provider: 'AWS CloudFront', cname: /\.cloudfront\.net\.?$/i, body: /Bad request|ERROR: The request could not be satisfied/i },
  { provider: 'Heroku', cname: /\.herokudns\.com\.?$|\.herokuapp\.com\.?$/i, body: /No such app|herokucdn\.com\/error-pages\/no-such-app/i },
  { provider: 'Fastly', cname: /\.fastly\.net\.?$/i, body: /Fastly error: unknown domain/i },
  { provider: 'Fly.io', cname: /\.fly\.dev\.?$/i, body: /404 Not Found|Could not find App/i },
  { provider: 'Cloudflare Pages', cname: /\.pages\.dev\.?$/i, body: /Project not found|Nothing here yet/i },
  { provider: 'Azure', cname: /\.(?:azurewebsites\.net|cloudapp\.net|blob\.core\.windows\.net)\.?$/i, body: /404 Web Site not found|InvalidUri/i },
  { provider: 'Shopify', cname: /\.myshopify\.com\.?$/i, body: /Sorry, this shop is currently unavailable/i },
  { provider: 'Ghost', cname: /\.ghost\.io\.?$/i, body: /The thing you were looking for is no longer here/i },
  { provider: 'Surge', cname: /\.surge\.sh\.?$/i, body: /project not found/i },
  { provider: 'Render', cname: /\.onrender\.com\.?$/i, body: /Not Found|This service has been suspended/i },
  { provider: 'Railway', cname: /\.up\.railway\.app\.?$/i, body: /Application not found/i },
  { provider: 'Webflow', cname: /\.webflow\.io\.?$|proxy-ssl\.webflow\.com\.?$/i, body: /The page you are looking for doesn't exist or has been moved/i },
]

export function dnsTakeoverAnalyze(input: {
  hostname?: string; cnames?: string[]; a?: string[]; aaaa?: string[]; status?: number; body?: string; nxdomain?: boolean
}): Record<string, unknown> {
  const cnames = input.cnames ?? []
  const body = input.body ?? ''
  const matchedProviders: Array<{ provider: string; cname: string; bodyMatched: boolean; nxdomain: boolean }> = []
  for (const cname of cnames) {
    for (const sig of takeoverSignatures) {
      if (sig.cname.test(cname)) {
        matchedProviders.push({
          provider: sig.provider,
          cname,
          bodyMatched: sig.body.test(body),
          nxdomain: Boolean(input.nxdomain),
        })
      }
    }
  }
  const danglingNoIp = cnames.length > 0 && (input.a?.length ?? 0) === 0 && (input.aaaa?.length ?? 0) === 0
  return {
    hostname: input.hostname,
    cnames,
    danglingNoIp,
    nxdomain: Boolean(input.nxdomain),
    matchedProviders,
    likelyTakeover: matchedProviders.some(m => m.bodyMatched || m.nxdomain),
  }
}

export function techFingerprint(input: {
  headers?: Record<string, string>
  body?: string
  url?: string
  packageJson?: string
}): Record<string, unknown> {
  const headers = Object.fromEntries(Object.entries(input.headers ?? {}).map(([k, v]) => [k.toLowerCase(), v]))
  const body = input.body ?? ''
  const detected: Array<{ ecosystem: string; package: string; version?: string; confidence: 'high' | 'medium' | 'low'; signal: string }> = []
  const add = (ecosystem: string, pkg: string, version: string | undefined, confidence: 'high' | 'medium' | 'low', signal: string) => {
    if (!detected.some(item => item.ecosystem === ecosystem && item.package === pkg && item.version === version)) {
      detected.push({ ecosystem, package: pkg, ...(version ? { version } : {}), confidence, signal })
    }
  }

  const powered = headers['x-powered-by'] ?? ''
  const server = headers['server'] ?? ''
  if (/next\.js/i.test(powered) || headers['x-nextjs-cache'] || headers['x-nextjs-prerender'] || body.includes('/_next/static/') || body.includes('__NEXT_DATA__')) {
    const ver = powered.match(/next\.js\s+([\d.]+)/i)?.[1] ?? body.match(/next(?:\/dist)?@?([\d]+\.[\d]+\.[\d]+)/i)?.[1]
    add('npm', 'next', ver, ver ? 'high' : 'medium', ver ? `Next.js version signal (${ver})` : 'Next.js runtime headers/chunks')
  }
  if (/express/i.test(powered)) add('npm', 'express', powered.match(/express\/?([\d.]+)/i)?.[1], 'medium', `X-Powered-By: ${powered}`)
  if (/nginx\/([\d.]+)/i.test(server)) add('Debian', 'nginx', server.match(/nginx\/([\d.]+)/i)?.[1], 'high', `Server: ${server}`)
  if (/apache\/([\d.]+)/i.test(server)) add('Debian', 'apache2', server.match(/apache\/([\d.]+)/i)?.[1], 'high', `Server: ${server}`)
  if (/cloudflare/i.test(server) || headers['cf-ray']) add('infra', 'cloudflare', undefined, 'high', 'Cloudflare edge headers')
  if (/vercel/i.test(server) || headers['x-vercel-id']) add('infra', 'vercel', undefined, 'high', 'Vercel edge headers')
  if (headers['x-clerk-auth-status'] || body.includes('clerk.accounts') || /pk_(?:live|test)_[A-Za-z0-9]{15,}/.test(body)) {
    add('npm', '@clerk/nextjs', undefined, 'medium', 'Clerk auth headers/SDK markers')
  }
  if (body.includes('.supabase.co') || headers['x-supabase-api-version']) {
    add('npm', '@supabase/supabase-js', undefined, 'medium', 'Supabase client/API markers')
  }
  if (body.includes('react-dom') || body.includes('__REACT_DEVTOOLS') || /react@([\d.]+)/i.test(body)) {
    add('npm', 'react', body.match(/react(?:-dom)?@([\d]+\.[\d]+\.[\d]+)/i)?.[1], 'medium', 'React runtime markers')
  }
  if (body.includes('/@vite/client') || body.includes('__vite_plugin')) {
    add('npm', 'vite', body.match(/vite@([\d]+\.[\d]+\.[\d]+)/i)?.[1], 'high', 'Vite dev/client markers')
  }
  if (body.includes('graphql') || body.includes('__typename')) {
    add('npm', 'graphql', undefined, 'low', 'GraphQL client/schema markers')
  }
  if (input.packageJson) {
    try {
      const pkg = JSON.parse(input.packageJson) as { dependencies?: Record<string, string>; devDependencies?: Record<string, string> }
      for (const [name, rawVer] of Object.entries({ ...pkg.dependencies, ...pkg.devDependencies })) {
        const clean = rawVer.replace(/^[^\d]*/, '')
        if (/^\d+\.\d+/.test(clean)) add('npm', name, clean, 'high', `package.json dependency ${name}@${rawVer}`)
      }
    } catch {
      // ignore invalid packageJson
    }
  }
  return { url: input.url, count: detected.length, technologies: detected.slice(0, 100) }
}

export function runAnalyzer(tool: AnalyzerName, args: Record<string, unknown>, readEvidence: (name: string) => string): Record<string, unknown> {
  const file = typeof args.file === 'string' ? args.file : undefined
  const content = file ? readEvidence(file) : typeof args.text === 'string' ? args.text : ''
  switch (tool) {
    case 'js-harvest':
      return jsHarvest(content, file ?? 'inline')
    case 'secret-scan':
      return secretScan(content, file ?? 'inline')
    case 'jwt-inspect':
      return jwtInspect(content)
    case 'graphql-parse':
      return graphqlParse(content)
    case 'openapi-parse':
      return openapiParse(content)
    case 'tech-fingerprint': {
      const payload = file ? JSON.parse(content) as Parameters<typeof techFingerprint>[0] : args as Parameters<typeof techFingerprint>[0]
      return techFingerprint(payload)
    }
    case 'diff-response': {
      const control = typeof args.controlFile === 'string'
        ? JSON.parse(readEvidence(args.controlFile)) as { status?: number; body?: string; mediaType?: string }
        : (args.control as { status?: number; body?: string; mediaType?: string }) ?? {}
      const probe = typeof args.probeFile === 'string'
        ? JSON.parse(readEvidence(args.probeFile)) as { status?: number; body?: string; mediaType?: string }
        : (args.probe as { status?: number; body?: string; mediaType?: string }) ?? {}
      return diffResponse(control, probe)
    }
    case 'dns-takeover': {
      const payload = file ? JSON.parse(content) as Parameters<typeof dnsTakeoverAnalyze>[0] : args as Parameters<typeof dnsTakeoverAnalyze>[0]
      return dnsTakeoverAnalyze(payload)
    }
  }
}
