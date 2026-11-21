import { createFileRoute } from '@tanstack/react-router'
import { id } from '../domain.ts'
import { store } from '../server/store.ts'

function eventsResponse(request: Request, runId: string) {
  if (!id.safeParse(runId).success) return new Response('Invalid run ID.', { status: 400 })
  const db = store()
  try {
    db.run(runId)
  } catch {
    return new Response('Run not found.', { status: 404 })
  }
  const url = new URL(request.url)
  const supplied = request.headers.get('last-event-id') ?? url.searchParams.get('since') ?? '0'
  let cursor = Number(supplied)
  if (!Number.isSafeInteger(cursor) || cursor < 0) return new Response('Invalid event cursor.', { status: 400 })
  let stop = () => {}
  const encoder = new TextEncoder()
  const stream = new ReadableStream<Uint8Array>({
    start(controller) {
      let closed = false
      let lastWrite = Date.now()
      const write = (chunk: string) => {
        if (closed) return
        controller.enqueue(encoder.encode(chunk))
        lastWrite = Date.now()
      }
      const flush = () => {
        if (closed || (controller.desiredSize ?? 0) <= 0) return
        try {
          while (!closed) {
            const batch = db.eventsAfter(runId, cursor, 1000)
            if (!batch.length) break
            write(batch.map(event => `id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`).join(''))
            cursor = batch.at(-1)!.id
            if (batch.length < 1000) break
          }
        } catch {
          stop()
          if (!closed) {
            closed = true
            controller.error(new Error('Cannot read run events.'))
          }
        }
      }
      const unsubscribe = db.onRunEvent(runId, () => flush())
      const keepalive = setInterval(() => {
        if (closed) return
        flush()
        if (Date.now() - lastWrite >= 15_000) write(': keepalive\n\n')
      }, 15_000)
      keepalive.unref?.()
      const abort = () => {
        stop()
        if (!closed) {
          closed = true
          try { controller.close() } catch { /* already closed */ }
        }
      }
      stop = () => {
        unsubscribe()
        clearInterval(keepalive)
        request.signal.removeEventListener('abort', abort)
      }
      request.signal.addEventListener('abort', abort, { once: true })
      write('retry: 700\n\n')
      flush()
      if (request.signal.aborted) abort()
    },
    cancel() {
      stop()
    },
  })
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
