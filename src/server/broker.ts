import { lookup } from 'node:dns/promises'
import { request } from 'node:https'
import type { IncomingHttpHeaders } from 'node:http'
import ipaddr from 'ipaddr.js'
import { referrerPolicies } from '../domain.ts'
import type { PreparedObservation } from '../domain.ts'

export interface PublicObservation extends PreparedObservation {
  origin: string
  finalOrigin: string
  source: 'public response' | 'fixture response' | 'supplied observation'
}

type HeadersRead = { status: number; headers: IncomingHttpHeaders }
type PublicAddress = { address: string; family: number }
type Resolver = (host: string) => Promise<PublicAddress[]>
type Transport = (url: URL, address: PublicAddress, signal: AbortSignal) => Promise<HeadersRead>

async function resolveBeforeDeadline(resolve: Resolver, hostname: string, signal: AbortSignal) {
  let cancel = () => {}
  try {
    const aborted = new Promise<never>((_resolve, reject) => {
      cancel = () => reject(signal.reason)
      signal.addEventListener('abort', cancel, { once: true })
      if (signal.aborted) cancel()
    })
    return await Promise.race([aborted, resolve(hostname)])
  } finally {
    signal.removeEventListener('abort', cancel)
  }
}

export class BrokerDenied extends Error {
  constructor(message: string) {
    super(message)
    this.name = 'BrokerDenied'
  }
}

function isPublic({ address }: PublicAddress) {
  try {
    const ip = ipaddr.process(address)
    if (ip.range() !== 'unicast') return false
    // Standard IPv6 global unicast prefix. IPv4-mapped addresses are reduced
    // to IPv4 by ipaddr.process before the range test.
    return ip.kind() === 'ipv4' || ip.toByteArray()[0] >> 5 === 1
  } catch {
    return false
  }
}

function header(headers: IncomingHttpHeaders, key: string) {
  const value = headers[key]
  return Array.isArray(value) ? value.join(', ') : value
}

function referrerPolicy(value: string | undefined): PublicObservation['referrerPolicy'] {
  if (value === undefined) return 'absent'
  // Treat quoted lists as ambiguous so embedded commas cannot produce a false policy finding.
  if (value.includes('"')) return 'unrecognized'
  const tokens = value.split(',').map(token => token.trim())
  return tokens.findLast((token): token is typeof referrerPolicies[number] =>
    referrerPolicies.some(policy => policy === token)) ?? 'unrecognized'
}

function contentSecurityPolicy(headers: IncomingHttpHeaders): PublicObservation['contentSecurityPolicy'] {
  const enforced = header(headers, 'content-security-policy')
  const reportOnly = header(headers, 'content-security-policy-report-only')
  if (enforced !== undefined) return enforced.trim() ? 'enforced' : 'unrecognized'
  if (reportOnly !== undefined) return reportOnly.trim() ? 'report-only' : 'unrecognized'
  return 'absent'
}

function frameProtection(headers: IncomingHttpHeaders): PublicObservation['frameProtection'] {
  const csp = header(headers, 'content-security-policy')
  const xfo = header(headers, 'x-frame-options')
  const frameAncestors = Boolean(csp && /(?:^|;)\s*frame-ancestors\s+[^;]+/i.test(csp))
  const validXfo = Boolean(xfo && /^(?:deny|sameorigin)\s*$/i.test(xfo.split(',', 1)[0]))
  if (frameAncestors && validXfo) return 'both'
  if (frameAncestors) return 'csp-frame-ancestors'
  if (validXfo) return 'x-frame-options'
  if (xfo !== undefined) return 'unrecognized'
  return 'absent'
}

function serverDisclosure(headers: IncomingHttpHeaders): PublicObservation['serverDisclosure'] {
  if (header(headers, 'x-powered-by')) return 'technology'
  const server = header(headers, 'server')?.trim()
  if (!server) return 'absent'
  return /(?:\d|\/|next|express|php|asp\.net|nginx|apache)/i.test(server) ? 'technology' : 'generic'
}

function safePage(url: URL) {
  return url.protocol === 'https:' && !url.port && !url.username && !url.password &&
    !url.search && !url.hash && url.pathname.length <= 512 && !url.pathname.startsWith('//')
}

function httpsRead(url: URL, address: PublicAddress, signal: AbortSignal): Promise<HeadersRead> {
  return new Promise((resolve, reject) => {
    // Dial the checked address directly and verify TLS against the approved hostname.
    const req = request({
      hostname: address.address, servername: url.hostname, port: 443,
      path: url.pathname, method: 'GET', agent: false, rejectUnauthorized: true, signal,
      headers: {
        Host: url.host, Accept: 'text/html, application/json;q=0.8, */*;q=0.1',
        'User-Agent': 'Guardian/1 public evidence review',
      },
    }, res => {
      resolve({ status: res.statusCode ?? 0, headers: res.headers })
      res.destroy()
    })
    req.once('error', reject)
    req.end()
  })
}

function observed(origin: string, url: URL, response: HeadersRead, source: PublicObservation['source']): PublicObservation {
  const transport = header(response.headers, 'strict-transport-security') ?? ''
  const ages = transport.split(';').filter(directive => /^\s*max-age\s*(?:=|$)/i.test(directive))
  const parsed = ages.length === 1 ? ages[0].match(/^\s*max-age\s*=\s*(?:"(\d+)"|(\d+))\s*$/i) : null
  const maxAge = parsed ? Number(parsed[1] ?? parsed[2]) : NaN
  const rawType = header(response.headers, 'content-type')?.split(';', 1)[0].trim().toLowerCase() ?? ''
  const typeOptions = header(response.headers, 'x-content-type-options')
  const nosniff = typeOptions?.split(',', 1)[0].trim().toLowerCase() === 'nosniff'
  return {
    origin,
    finalOrigin: url.origin,
    status: response.status,
    mediaType: /^[a-z0-9.+-]{1,40}\/[a-z0-9.+-]{1,60}$/.test(rawType) ? rawType : 'unknown',
    transportMaxAge: Number.isSafeInteger(maxAge) && maxAge >= 0 ? maxAge : null,
    includeSubDomains: /(?:^|;)\s*includeSubDomains\s*(?:;|$)/i.test(transport),
    source,
    contentTypeOptions: typeOptions === undefined ? 'absent' : nosniff ? 'nosniff' : 'unrecognized',
    referrerPolicy: referrerPolicy(header(response.headers, 'referrer-policy')),
    contentSecurityPolicy: contentSecurityPolicy(response.headers),
    frameProtection: frameProtection(response.headers),
    serverDisclosure: serverDisclosure(response.headers),
  }
}

type Grant = {
  origin: string
  canRead: (origin: string) => boolean
  audit: (outcome: 'allowed' | 'denied' | 'observed', origin: string, status?: number) => void
}

type BrokerOptions = {
  resolve?: Resolver
  transport?: Transport
  source?: PublicObservation['source']
}

export class RequestBroker {
  private readonly options: BrokerOptions

  constructor(options: BrokerOptions = {}) {
    this.options = options
  }

  async readPublicRoot(grant: Grant, signal: AbortSignal): Promise<PublicObservation> {
    const deadline = AbortSignal.any([signal, AbortSignal.timeout(12_000)])
    const resolve = this.options.resolve ?? ((host: string) => lookup(host, { all: true, order: 'verbatim' }))
    const transport = this.options.transport ?? httpsRead
    let url = new URL('/', grant.origin)
    const deny = (message: string): never => {
      grant.audit('denied', url.origin)
      throw new BrokerDenied(message)
    }
    const check = () => {
      deadline.throwIfAborted()
      if (!safePage(url) || !grant.canRead(url.origin)) deny('Destination is outside the current assignment scope.')
    }
    for (let redirect = 0; redirect <= 3; redirect += 1) {
      check()
      const addresses = await resolveBeforeDeadline(resolve, url.hostname, deadline)
      check()
      if (addresses.length === 0 || addresses.some(address => !isPublic(address))) {
        deny('The public hostname did not resolve exclusively to public addresses.')
      }
      grant.audit('allowed', url.origin)
      const response = await transport(url, addresses.find(address => address.family === 4) ?? addresses[0], deadline)
      check()
      grant.audit('observed', url.origin, response.status)
      if (![301, 302, 303, 307, 308].includes(response.status)) {
        return observed(grant.origin, url, response, this.options.source ?? 'public response')
      }
      const location = response.headers.location
      if (!location || redirect === 3) return deny('The public response could not be followed within the redirect limit.')
      try {
        url = new URL(location, url)
      } catch {
        deny('The redirect destination is invalid.')
      }
    }
    return deny('The public response exceeded the redirect limit.')
  }
}
