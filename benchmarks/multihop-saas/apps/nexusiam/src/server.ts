// Boot all five loopback services. Every listener goes through lib/safety.ts (127.0.0.1:0).
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { createEgress } from '../../../lib/egress.ts'
import type { Egress } from '../../../lib/egress.ts'
import { assertLocalLabAllowed, closeServer, listenLoopback, originOf } from '../../../lib/safety.ts'
import type { LabState, ServiceName } from './shared.ts'
import { sendJson } from './http.ts'
import { handleCdn } from './service-cdn.ts'
import { handleApp } from './service-app.ts'
import { handleApi } from './service-api.ts'
import { handleIdp } from './service-idp.ts'
import { handleDocsWorker } from './service-docs-worker.ts'

export interface RunningLab {
  origins: Record<ServiceName, string>
  egress: Egress
  close(): Promise<void>
}

function failure(res: ServerResponse, err: unknown): void {
  if (res.headersSent) {
    res.destroy()
    return
  }
  sendJson(res, 500, { error: 'internal lab error', detail: (err as Error).message.slice(0, 160) })
}

export async function startServices(state: LabState): Promise<RunningLab> {
  assertLocalLabAllowed()
  const origins = {} as Record<ServiceName, string>
  const egress = createEgress()

  const cdn = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleCdn(req, res, state).catch((err) => failure(res, err))
  })
  const app = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleApp(req, res, state, egress).catch((err) => failure(res, err))
  })
  const api = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleApi(req, res, state, { egress, idpOrigin: origins.idp ?? '' }).catch((err) => failure(res, err))
  })
  const idp = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleIdp(req, res, state).catch((err) => failure(res, err))
  })
  const docsWorker = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleDocsWorker(req, res, state).catch((err) => failure(res, err))
  })

  const entries: Array<[ServiceName, typeof cdn]> = [
    ['cdn', cdn], ['app', app], ['api', api], ['idp', idp], ['docs-worker', docsWorker],
  ]
  try {
    const ports = await Promise.all(entries.map(([, server]) => listenLoopback(server)))
    for (let i = 0; i < entries.length; i++) {
      const [name] = entries[i]!
      origins[name] = originOf(ports[i]!)
      egress.register({ name, origin: origins[name]!, internal: name === 'docs-worker' })
    }
  } catch (err) {
    await Promise.all(entries.map(([, server]) => closeServer(server)))
    throw err
  }

  return {
    origins,
    egress,
    async close() {
      await Promise.all(entries.map(([, server]) => closeServer(server)))
    },
  }
}
