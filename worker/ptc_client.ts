/**
 * Zero-dependency PTC client SDK for Kovo sandboxed code execution.
 * Speaks JSON-over-HTTP across `/kovo-ptc/ptc.sock` using `node:http` & `node:fs` only.
 */
import { readFileSync } from 'node:fs'
import { request as httpRequest } from 'node:http'

export interface PtcClientOptions {
  socketPath?: string
  tokenFile?: string
  timeoutMs?: number
}

export interface PtcHttpOptions {
  as?: string
  persona?: string
  origin?: string
  headers?: Record<string, string>
  body?: unknown
  followRedirects?: boolean
  timeoutMs?: number
  [key: string]: unknown
}

export interface PtcHttpRequest extends PtcHttpOptions {
  method?: string
  pathAndQuery?: string
  path?: string
  url?: string
}

export interface PtcHttpResponse {
  exchangeId?: string
  stagedPath?: string | null
  origin?: string
  finalOrigin?: string
  redirectOrigins?: string[]
  status?: number
  mediaType?: string
  respHeaders?: Record<string, string | string[]>
  setCookies?: string[]
  bodyBytes?: number
  bodySha256?: string
  bodyPreview?: string
  durationMs?: number
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  json?: any
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  body?: any
  text?: string
  [key: string]: unknown
}

export interface PtcBatchResponse {
  count?: number
  stagedPath?: string | null
  results?: PtcHttpResponse[]
  [key: string]: unknown
}

export interface PtcRaceResponse extends PtcBatchResponse {
  summary?: Record<string, unknown>
}

export interface KovoPtcClient {
  http(method: string, pathAndQuery: string, opts?: PtcHttpOptions): Promise<unknown>
  http(opts: PtcHttpRequest): Promise<unknown>
  batch(requests: PtcHttpRequest[] | Record<string, unknown>, opts?: Record<string, unknown>): Promise<unknown>
  race(requests: PtcHttpRequest[] | Record<string, unknown>, opts?: Record<string, unknown>): Promise<unknown>
  browser(args: Record<string, unknown>): Promise<unknown>
  oob(args: Record<string, unknown>): Promise<unknown>
  probe(args: Record<string, unknown>): Promise<unknown>
  analyze(args: Record<string, unknown>): Promise<unknown>
  searchRun(args: Record<string, unknown>): Promise<unknown>
  search_run(args: Record<string, unknown>): Promise<unknown>
  repo(args: Record<string, unknown>): Promise<unknown>
  search_repo(args: Record<string, unknown>): Promise<unknown>
  read_repo_file(args: Record<string, unknown>): Promise<unknown>
  list_repo_files(args?: Record<string, unknown>): Promise<unknown>
  recordFact(args: Record<string, unknown>): Promise<unknown>
  record_fact(args: Record<string, unknown>): Promise<unknown>
  queryCves(args: Record<string, unknown>): Promise<unknown>
  query_cves(args: Record<string, unknown>): Promise<unknown>
}

interface RpcEnvelope {
  ok: boolean
  result?: unknown
  error?: string
}

const MAX_RESPONSE_BYTES = 8 * 1024 * 1024
const SEARCH_RUN_TARGETS = new Set(['endpoints', 'exchanges', 'exchange_detail', 'facts', 'peer_traces'])

function tryParseJsonObjectOrArray(raw: string): Record<string, unknown> | unknown[] | null {
  const trimmed = raw.trim()
  if (!trimmed || (trimmed[0] !== '{' && trimmed[0] !== '[')) return null
  try {
    const parsed: unknown = JSON.parse(trimmed)
    if (parsed !== null && typeof parsed === 'object') {
      return parsed as Record<string, unknown> | unknown[]
    }
  } catch {
    /* non-JSON or truncated JSON preview */
  }
  return null
}

/**
 * Hydrate a single HTTP response object with auto-parsed `json`, `body`, and `text`
 * convenience properties while preserving every original field intact.
 */
export function hydrateHttpResponse(value: unknown): unknown {
  if (!value || typeof value !== 'object' || Array.isArray(value)) return value
  const rec = value as Record<string, unknown>
  if (typeof rec.bodyPreview !== 'string') return value
  const parsed = tryParseJsonObjectOrArray(rec.bodyPreview)
  return {
    ...rec,
    json: parsed,
    body: parsed !== null ? parsed : rec.bodyPreview,
    text: rec.bodyPreview,
  }
}

/**
 * Hydrate single, batch, or race HTTP RPC results (`res`, `res.results[]`, or raw arrays).
 */
export function hydrateHttpResult(value: unknown): unknown {
  if (Array.isArray(value)) return value.map(hydrateHttpResponse)
  if (!value || typeof value !== 'object') return value
  const rec = value as Record<string, unknown>
  if (Array.isArray(rec.results)) {
    return { ...rec, results: rec.results.map(hydrateHttpResponse) }
  }
  return hydrateHttpResponse(rec)
}

function normalizeSearchRunArgs(args: Record<string, unknown>): Record<string, unknown> {
  if (!args || typeof args !== 'object') return {}
  if (typeof args.target === 'string' && args.target.trim()) return args
  if (typeof args.kind === 'string' && SEARCH_RUN_TARGETS.has(args.kind.trim())) {
    const { kind, ...rest } = args
    return { ...rest, target: kind.trim() }
  }
  return args
}

function normalizeHttpArgs(
  methodOrOpts: string | PtcHttpRequest,
  pathAndQuery?: string | PtcHttpOptions,
  opts?: PtcHttpOptions,
): Record<string, unknown> {
  if (typeof methodOrOpts === 'object' && methodOrOpts !== null) {
    const out: Record<string, unknown> = { ...methodOrOpts }
    if (typeof out.method === 'string') out.method = out.method.toUpperCase()
    return out
  }
  if (typeof pathAndQuery === 'string') {
    return { ...(opts ?? {}), method: methodOrOpts.toUpperCase(), pathAndQuery }
  }
  const extra = pathAndQuery && typeof pathAndQuery === 'object' ? pathAndQuery : opts
  return { ...(extra ?? {}), method: 'GET', pathAndQuery: methodOrOpts }
}

export function createKovoClient(opts: PtcClientOptions = {}): KovoPtcClient {
  const socketPath = opts.socketPath ?? process.env.KOVO_PTC_SOCKET ?? '/kovo-ptc/ptc.sock'
  const tokenFile = opts.tokenFile ?? process.env.KOVO_PTC_TOKEN_FILE ?? '/kovo-ptc/token'
  const defaultTimeoutMs = Math.max(100, opts.timeoutMs ?? 60_000)
  let cachedToken: string | null = null

  const getToken = (): string => {
    if (cachedToken === null) cachedToken = readFileSync(tokenFile, 'utf8').trim()
    return cachedToken
  }

  const rpc = (op: string, args: Record<string, unknown> = {}, timeoutMs = defaultTimeoutMs): Promise<unknown> => {
    const payload = JSON.stringify({ op, args })
    return new Promise((resolve, reject) => {
      const req = httpRequest(
        {
          socketPath,
          path: '/rpc',
          method: 'POST',
          timeout: timeoutMs,
          headers: {
            'content-type': 'application/json',
            'content-length': Buffer.byteLength(payload),
            'x-kovo-rpc-token': getToken(),
          },
        },
        res => {
          const chunks: Buffer[] = []
          let size = 0
          res.on('data', (chunk: Buffer) => {
            size += chunk.length
            if (size > MAX_RESPONSE_BYTES) {
              res.destroy()
              reject(new Error('PTC RPC response exceeded 8 MiB limit.'))
              return
            }
            chunks.push(chunk)
          })
          res.on('end', () => {
            let envelope: RpcEnvelope
            try { envelope = JSON.parse(Buffer.concat(chunks).toString('utf8')) as RpcEnvelope } catch {
              reject(new Error(`PTC RPC returned malformed JSON (HTTP ${res.statusCode ?? 0}).`))
              return
            }
            if ((res.statusCode ?? 500) >= 400 || !envelope.ok) {
              reject(new Error(envelope.error ?? `PTC RPC call failed (HTTP ${res.statusCode ?? 0}).`))
              return
            }
            resolve(envelope.result)
          })
        },
      )
      req.on('timeout', () => req.destroy(new Error(`PTC RPC call "${op}" timed out.`)))
      req.on('error', reject)
      req.end(payload)
    })
  }

  const http = (
    methodOrOpts: string | PtcHttpRequest,
    pathAndQuery?: string | PtcHttpOptions,
    extra?: PtcHttpOptions,
  ): Promise<unknown> => rpc('http', normalizeHttpArgs(methodOrOpts, pathAndQuery, extra)).then(hydrateHttpResult)

  const batch: KovoPtcClient['batch'] = (requests, extra) =>
    rpc('http', Array.isArray(requests) ? { ...(extra ?? {}), mode: 'batch', requests } : { ...requests, mode: 'batch' }).then(hydrateHttpResult)

  const race: KovoPtcClient['race'] = (requests, extra) =>
    rpc('http', Array.isArray(requests) ? { ...(extra ?? {}), mode: 'race', requests } : { ...requests, mode: 'race' }).then(hydrateHttpResult)

  const searchRun: KovoPtcClient['searchRun'] = args => rpc('searchRun', normalizeSearchRunArgs(args))
  const repo: KovoPtcClient['repo'] = args => rpc('repo', args)
  const recordFact: KovoPtcClient['recordFact'] = args => rpc('recordFact', args)
  const queryCves: KovoPtcClient['queryCves'] = args => rpc('queryCves', args)

  return {
    http: http as KovoPtcClient['http'],
    batch,
    race,
    browser: args => rpc('browser', args),
    oob: args => rpc('oob', args),
    probe: args => rpc('probe', args),
    analyze: args => rpc('analyze', args),
    searchRun,
    search_run: args => searchRun(args),
    repo,
    search_repo: args => repo({ ...(args ?? {}), action: 'search' }),
    read_repo_file: args => repo({ ...(args ?? {}), action: 'read' }),
    list_repo_files: (args = {}) => repo({ ...args, action: 'list' }),
    recordFact,
    record_fact: args => recordFact(args),
    queryCves,
    query_cves: args => queryCves(args),
  }
}
