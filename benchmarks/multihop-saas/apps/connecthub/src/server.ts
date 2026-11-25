// Boot all five connecthub loopback services. Every listener goes through lib/safety.ts.
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { createEgress } from '../../../lib/egress.ts'
import type { Egress } from '../../../lib/egress.ts'
import { assertLocalLabAllowed, closeServer, listenLoopback, originOf } from '../../../lib/safety.ts'
import type { LabState, ServiceName } from './shared.ts'
import { sendJson } from './http.ts'
import { handlePortal } from './service-portal.ts'
import { handleApi } from './service-api.ts'
import { handleOauth } from './service-oauth.ts'
import { handleRelay } from './service-relay.ts'
import { handleBilling } from './service-billing.ts'

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

  const portal = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handlePortal(req, res, state, { egress }).catch((err) => failure(res, err))
  })
  const api = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleApi(req, res, state, { egress }).catch((err) => failure(res, err))
  })
  const oauth = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleOauth(req, res, state).catch((err) => failure(res, err))
  })
  const relay = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleRelay(req, res, state).catch((err) => failure(res, err))
  })
  const billing = createServer((req: IncomingMessage, res: ServerResponse) => {
    void handleBilling(req, res, state).catch((err) => failure(res, err))
  })

  const entries: Array<[ServiceName, typeof portal]> = [
    ['portal', portal], ['api', api], ['oauth', oauth],
    ['webhook-relay', relay], ['billing.internal', billing],
  ]
  try {
    const ports = await Promise.all(entries.map(([, server]) => listenLoopback(server)))
    for (let i = 0; i < entries.length; i++) {
      const [name] = entries[i]!
      origins[name] = originOf(ports[i]!)
      egress.register({
        name,
        origin: origins[name]!,
        internal: name === 'webhook-relay' || name === 'billing.internal',
      })
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
