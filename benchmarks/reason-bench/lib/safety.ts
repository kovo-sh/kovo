// Containment guard for the offline benchmark lab. Nothing here starts unless explicitly enabled.
import type { Server } from 'node:http'
import type { AddressInfo } from 'node:net'

export const LOOPBACK = '127.0.0.1'

export function localLabAllowed(): boolean {
  return process.env.KOVO_ALLOW_LOCAL_LAB === '1'
}

export function assertLocalLabAllowed(): void {
  if (!localLabAllowed()) {
    throw new Error(
      'reason-bench refuses to start: set KOVO_ALLOW_LOCAL_LAB=1 to run the offline loopback lab.',
    )
  }
}

/** Listen on 127.0.0.1 with an OS-assigned port; resolve the chosen port. */
export function listenLoopback(server: Server): Promise<number> {
  return new Promise((resolve, reject) => {
    server.once('error', reject)
    server.listen(0, LOOPBACK, () => {
      const addr = server.address() as AddressInfo
      server.removeListener('error', reject)
      resolve(addr.port)
    })
  })
}

export function closeServer(server: Server): Promise<void> {
  return new Promise((resolve) => server.close(() => resolve()))
}
