// Bounded outbound client for service-to-service calls inside the lab. Only registered loopback
// origins are reachable, redirects are never followed, and every attempt is logged.
import { assertLocalLabAllowed, assertLoopbackUrl } from './safety.ts'

export interface EgressTarget {
  name: string
  origin: string
  internal: boolean
}

export interface EgressAttempt {
  seq: number
  ts: number
  target: string
  path: string
  method: string
  allowed: boolean
  status?: number
  reason?: string
}

export interface Egress {
  register(target: EgressTarget): void
  fetch(name: string, path: string, init?: RequestInit): Promise<Response>
  attempts(): EgressAttempt[]
  reset(): void
}

const MAX_BODY_BYTES = 64 * 1024
const TIMEOUT_MS = 2000

export function createEgress(targets: readonly EgressTarget[] = []): Egress {
  const registry = new Map<string, EgressTarget>()
  const log: EgressAttempt[] = []
  let seq = 0
  for (const target of targets) registry.set(target.name, target)

  const record = (partial: Omit<EgressAttempt, 'seq' | 'ts'>): void => {
    log.push({ seq: seq++, ts: Date.now(), ...partial })
  }

  return {
    register(target) {
      assertLoopbackUrl(target.origin)
      registry.set(target.name, target)
    },
    async fetch(name, path, init = {}) {
      assertLocalLabAllowed()
      const target = registry.get(name)
      if (!target) {
        record({ target: name, path, method: init.method ?? 'GET', allowed: false, reason: 'target_blocked' })
        throw new Error(`egress blocked: unregistered target '${name}'`)
      }
      if (!path.startsWith('/')) {
        record({ target: name, path, method: init.method ?? 'GET', allowed: false, reason: 'path_blocked' })
        throw new Error('egress blocked: path must start with /')
      }
      const url = assertLoopbackUrl(target.origin + path)
      if (url.port !== new URL(target.origin).port) {
        record({ target: name, path, method: init.method ?? 'GET', allowed: false, reason: 'port_blocked' })
        throw new Error('egress blocked: port mismatch')
      }
      try {
        const res = await fetch(url, {
          ...init,
          redirect: 'manual',
          signal: AbortSignal.timeout(TIMEOUT_MS),
        })
        record({ target: name, path, method: init.method ?? 'GET', allowed: true, status: res.status })
        const body = await res.text()
        if (Buffer.byteLength(body) > MAX_BODY_BYTES) {
          throw new Error('egress blocked: response too large')
        }
        return new Response(body, { status: res.status, headers: res.headers })
      } catch (err) {
        record({ target: name, path, method: init.method ?? 'GET', allowed: false, reason: 'transport_error' })
        throw err
      }
    },
    attempts() {
      return log.slice()
    },
    reset() {
      log.length = 0
    },
  }
}
