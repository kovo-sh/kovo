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
      let lastWrite = Date.now()
      const write = (chunk: string) => {
        controller.enqueue(encoder.encode(chunk))
        lastWrite = Date.now()
      }
      const flush = () => {
        if ((controller.desiredSize ?? 0) <= 0) return
        try {
          const batch = db.eventsAfter(runId, cursor)
          if (batch.length) {
            write(batch.map(event => `id: ${event.id}\ndata: ${JSON.stringify(event)}\n\n`).join(''))
            cursor = batch.at(-1)!.id
          } else if (Date.now() - lastWrite >= 15_000) write(': keepalive\n\n')
        } catch {
          stop()
          controller.error(new Error('Cannot read run events.'))
        }
      }
      const interval = setInterval(flush, 350)
      const abort = () => {
        stop()
        controller.close()
      }
      stop = () => {
        clearInterval(interval)
        request.signal.removeEventListener('abort', abort)
      }
      request.signal.addEventListener('abort', abort, { once: true })
      write('retry: 700\n\n')
      if (request.signal.aborted) abort()
    },
    cancel() {
      stop()
    },
  })
  return new Response(stream, { headers: {
    'content-type': 'text/event-stream', 'cache-control': 'no-cache, no-transform', 'x-accel-buffering': 'no',
  } })
}

export const Route = createFileRoute('/api/runs/$runId/events')({
  server: { handlers: { GET: ({ request, params }) => eventsResponse(request, params.runId) } },
})
