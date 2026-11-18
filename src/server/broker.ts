import { lookup } from 'node:dns/promises'
import { request } from 'node:https'
import type { IncomingHttpHeaders } from 'node:http'
import ipaddr from 'ipaddr.js'

export interface PublicObservation {
  origin: string
  finalOrigin: string
  status: number
  mediaType: string
  transportMaxAge: number | null
  includeSubDomains: boolean
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
  return typeof value === 'string' ? value : ''
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
  const transport = header(response.headers, 'strict-transport-security')
  const parsed = transport.match(/(?:^|;)\s*max-age\s*=\s*(\d+)\s*(?:;|$)/i)
  const maxAge = parsed ? Number(parsed[1]) : NaN
  const rawType = header(response.headers, 'content-type').split(';', 1)[0].trim().toLowerCase()
  return {
    origin,
    finalOrigin: url.origin,
    status: response.status,
    mediaType: /^[a-z0-9.+-]{1,40}\/[a-z0-9.+-]{1,60}$/.test(rawType) ? rawType : 'unknown',
    transportMaxAge: Number.isSafeInteger(maxAge) && maxAge >= 0 ? maxAge : null,
    includeSubDomains: /(?:^|;)\s*includeSubDomains\s*(?:;|$)/i.test(transport),
    source,
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
      const location = header(response.headers, 'location')
      if (!location || redirect === 3) deny('The public response could not be followed within the redirect limit.')
      try {
        url = new URL(location, url)
      } catch {
        deny('The redirect destination is invalid.')
      }
    }
    return deny('The public response exceeded the redirect limit.')
  }
}
