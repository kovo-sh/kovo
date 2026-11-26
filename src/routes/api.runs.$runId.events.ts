import { createFileRoute } from '@tanstack/react-router'
import { id } from '../domain.ts'
import { getAppRuntime } from '../server/app-runtime.ts'
import { store } from '../server/store.ts'

export function eventsResponse(request: Request, runId: string) {
  if (!id.safeParse(runId).success) return new Response('Invalid run ID.', { status: 400 })
  const db = store()
  try {
    db.run(runId)
  } catch {
    return new Response('Run not found.', { status: 404 })
  }
  const runtime = getAppRuntime({ dataDir: db.directory })
  let runTenantId: string | null = null
  try {
    const resolvedTenant = db.getRunTenant(runId)
    runTenantId = resolvedTenant && resolvedTenant !== 'default' ? resolvedTenant : null
  } catch {
    runTenantId = null
  }
  if (runtime.killSwitch.isActive(runTenantId)) {
    return new Response(
      JSON.stringify({ error: 'Kill switch active.', code: 'KILL_SWITCH_TRIPPED' }),
      {
        status: 503,
        headers: {
          'content-type': 'application/json; charset=utf-8',
          'cache-control': 'no-store',
        },
      },
    )
  }
  const url = new URL(request.url)
  const supplied = request.headers.get('last-event-id') ?? url.searchParams.get('since') ?? '0'
  let cursor = Number(supplied)
  if (!Number.isSafeInteger(cursor) || cursor < 0) return new Response('Invalid event cursor.', { status: 400 })
  let closed = false
  let stopped = false
  let stop = () => {}
  const encoder = new TextEncoder()
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let lastWrite = Date.now()
      const write = (chunk: string) => {
        if (closed) return
        try {
          controller.enqueue(encoder.encode(chunk))
          lastWrite = Date.now()
        } catch {
          stop()
        }
      }
      const flush = () => {
        if (closed || (controller.desiredSize ?? 0) <= 0) return
        try {
          while (!closed) {
            const batch = db.eventsAfter(runId, cursor, 1000)
            if (!batch.length) break
            write(batch.map(event => `id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`).join(''))
            if (closed) break
            cursor = batch.at(-1)!.id
            if (batch.length < 1000) break
          }
        } catch {
          if (closed) return
          stop()
          try { controller.error(new Error('Cannot read run events.')) } catch { /* already closed */ }
        }
      }
      const unsubscribe = db.onRunEvent(runId, () => flush())
      const keepalive = setInterval(() => {
        if (closed) return
        flush()
        if (!closed && Date.now() - lastWrite >= 15_000) write(': keepalive\n\n')
      }, 15_000)
      keepalive.unref?.()
      const abort = () => {
        if (closed) return
        stop()
        try { controller.close() } catch { /* already closed */ }
      }
      const unsubscribeKillSwitch = runtime.killSwitch.onSseRevocation(state => {
        if (state.tenantId === null || (runTenantId !== null && state.tenantId === runTenantId)) {
          abort()
        }
      })
      stop = () => {
        closed = true
        if (stopped) return
        stopped = true
        unsubscribe()
        unsubscribeKillSwitch()
        clearInterval(keepalive)
        request.signal.removeEventListener('abort', abort)
      }
      request.signal.addEventListener('abort', abort, { once: true })
      if (runtime.killSwitch.isActive(runTenantId)) {
        abort()
        return
      }
      write('retry: 700\n\n')
      flush()
      if (request.signal.aborted) abort()
    },
    cancel() {
      closed = true
      stop()
    },
  }, { highWaterMark: 64 })
  return new Response(stream, {
    headers: {
      'content-type': 'text/event-stream',
      'cache-control': 'no-cache, no-transform',
      'x-accel-buffering': 'no',
    },
  })
}

export const Route = createFileRoute('/api/runs/$runId/events')({
  server: { handlers: { GET: ({ request, params }) => eventsResponse(request, params.runId) } },
})
