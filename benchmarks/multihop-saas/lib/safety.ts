// Containment guard for the offline multi-service lab. Nothing here starts unless explicitly enabled.
// This is the only module in the tree allowed to bind a socket, and it binds 127.0.0.1 port 0.
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'

export const LOOPBACK = '127.0.0.1'

export function localLabAllowed(): boolean {
  return process.env.KOVO_ALLOW_LOCAL_LAB === '1'
}

export function assertLocalLabAllowed(): void {
  if (!localLabAllowed()) {
    throw new Error(
      'multihop-saas refuses to start: set KOVO_ALLOW_LOCAL_LAB=1 to run the offline loopback lab.',
    )
  }
}

/** Listen on 127.0.0.1 with an OS-assigned ephemeral port; resolve the chosen port. */
export function listenLoopback(server: Server): Promise<number> {
  assertLocalLabAllowed()
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, LOOPBACK, () => {
      const addr = server.address() as AddressInfo
      server.removeListener('error', reject)
      if (addr.address !== LOOPBACK) {
        server.close()
        reject(new Error(`refusing non-loopback bind: ${addr.address}`))
        return
      }
      resolve(addr.port)
    })
  })
}

export function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()))
}

/** Reject any absolute URL whose host is not a literal loopback address. */
export function assertLoopbackUrl(raw: string): URL {
  const url = new URL(raw)
  if (url.hostname !== LOOPBACK) throw new Error(`refusing non-loopback URL host: ${url.hostname}`)
  if (url.protocol !== 'http:') throw new Error(`refusing non-http loopback URL: ${url.protocol}`)
  return url
}

export function originOf(port: number): string {
  return `http://${LOOPBACK}:${port}`
}
