// Containment guard for the realism suite. Nothing binds a socket unless the operator
// explicitly opts into the offline loopback lab.
import type { AddressInfo } from 'node:net'

export const LOOPBACK = '127.0.0.1'

export function localLabAllowed(): boolean {
  return process.env.KOVO_ALLOW_LOCAL_LAB === '1'
}

export function assertLocalLabAllowed(): void {
  if (!localLabAllowed()) {
    throw new Error(
      'realism-suite refuses to start: set KOVO_ALLOW_LOCAL_LAB=1 to run the offline loopback fixtures.',
    )
  }
}

/** Structural view shared by node:http servers and node:http2 servers. */
export interface Listenable {
  listen(port: number, host: string, callback: () => void): unknown
  once(event: 'error', listener: (err: Error) => void): unknown
  removeListener(event: 'error', listener: (err: Error) => void): unknown
  address(): AddressInfo | string | null
  close(callback?: () => void): unknown
}

/** Listen on 127.0.0.1 with an OS-assigned port and resolve the chosen port. */
export function listenLoopback(server: Listenable): Promise<number> {
  return new Promise((resolve, reject) => {
    const onError = (err: Error) => {
      server.removeListener('error', onError)
      reject(err)
    }
    server.once('error', onError)
    server.listen(0, LOOPBACK, () => {
      server.removeListener('error', onError)
      const addr = server.address()
      if (!addr || typeof addr === 'string') {
        reject(new Error('realism-suite: server did not report a TCP address'))
        return
      }
      resolve(addr.port)
    })
  })
}

/** Close a listening server and wait for the handle to be released. */
export function closeServer(server: { close(callback: () => void): unknown }): Promise<void> {
  return new Promise((resolve) => {
    let done = false
    const finish = () => {
      if (done) return
      done = true
      resolve()
    }
    try {
      server.close(finish)
    } catch {
      finish()
    }
  })
}

export function originFor(port: number): string {
  return `http://${LOOPBACK}:${port}`
}
