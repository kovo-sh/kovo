import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import test from 'node:test'
import { eventsResponse } from '../src/routes/api.runs.$runId.events.ts'
import { store } from '../src/server/store.ts'

function setupTempRun() {
  const prevDataDir = process.env.KOVO_DATA_DIR
  const dir = mkdtempSync(join(tmpdir(), 'kovo-sse-cancel-'))
  process.env.KOVO_DATA_DIR = dir
  const db = store()
  const project = db.createProject({
    requestId: randomUUID(),
    name: 'SSE Cancel Test',
    seeds: ['https://app.example.test'],
    environment: 'public',
  })
  const run = db.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify SSE stream cancellation safety',
    sourceMode: 'public',
    capabilityTier: 1,
    approvalPolicy: 'auto_review',
    approvedPersonaIds: [],
    budgetUsd: 5,
    budgetRequests: 0,
    maxRpsPerOrigin: 3,
    workerConcurrency: 2,
    workerMaxTurns: 20,
  })
  const cleanup = () => {
    if (prevDataDir === undefined) delete process.env.KOVO_DATA_DIR
    else process.env.KOVO_DATA_DIR = prevDataDir
    rmSync(dir, { recursive: true, force: true })
  }
  return { db, run, cleanup }
}

test('SSE stream cancel before request.signal abort does not throw or leak unhandled rejections', async (t) => {
  const { db, run, cleanup } = setupTempRun()
  const unhandled: unknown[] = []
  const onUnhandled = (err: unknown) => unhandled.push(err)
  process.on('unhandledRejection', onUnhandled)
  t.after(() => {
    process.off('unhandledRejection', onUnhandled)
    cleanup()
  })

  const ac = new AbortController()
  const req = new Request(`http://localhost/api/runs/${run.id}/events?since=0`, { signal: ac.signal })
  const res = eventsResponse(req, run.id)
  assert.equal(res.status, 200)
  assert.ok(res.body)

  const reader = res.body.getReader()
  const first = await reader.read()
  assert.equal(first.done, false)
  assert.match(new TextDecoder().decode(first.value), /^retry: 700/)

  // Cancel the ReadableStream before request.signal fires abort (simulates navigating away).
  await reader.cancel()

  // Subsequent DB events and late abort signal must be harmless no-ops.
  db.event(run.id, 'run.note', 'after cancel')
  ac.abort()
  await new Promise((r) => setTimeout(r, 20))

  assert.deepEqual(unhandled, [])
})

test('SSE stream cancel mid-flush (both write and catch paths) never throws or calls controller.error', async (t) => {
  const { db, run, cleanup } = setupTempRun()
  const unhandled: unknown[] = []
  const onUnhandled = (err: unknown) => unhandled.push(err)
  process.on('unhandledRejection', onUnhandled)
  t.after(() => {
    process.off('unhandledRejection', onUnhandled)
    cleanup()
  })

  // Case 1: cancel() happens during db.eventsAfter() before write() -> controller.enqueue()
  {
    const ac = new AbortController()
    const req = new Request(`http://localhost/api/runs/${run.id}/events?since=0`, { signal: ac.signal })
    const res = eventsResponse(req, run.id)
    assert.ok(res.body)
    const reader = res.body.getReader()
    await reader.read()

    const origEventsAfter = db.eventsAfter.bind(db)
    let triggered = false
    let cancelPromise: Promise<void> | undefined
    db.eventsAfter = ((...args: Parameters<typeof db.eventsAfter>) => {
      if (!triggered) {
        triggered = true
        cancelPromise = reader.cancel()
        return [{
          id: 999,
          runId: run.id,
          kind: 'run.note',
          payload: { message: 'mid-flush' },
          createdAt: Date.now(),
        }]
      }
      return origEventsAfter(...args)
    }) as typeof db.eventsAfter

    try {
      db.event(run.id, 'run.note', 'trigger-1')
      await cancelPromise
    } finally {
      db.eventsAfter = origEventsAfter
    }
    ac.abort()
  }

  // Case 2: cancel() happens during db.eventsAfter() and db.eventsAfter() throws -> flush() catch block
  {
    const ac = new AbortController()
    const req = new Request(`http://localhost/api/runs/${run.id}/events?since=0`, { signal: ac.signal })
    const res = eventsResponse(req, run.id)
    assert.ok(res.body)
    const reader = res.body.getReader()
    await reader.read()

    const origEventsAfter = db.eventsAfter.bind(db)
    let triggered = false
    let cancelPromise: Promise<void> | undefined
    db.eventsAfter = ((...args: Parameters<typeof db.eventsAfter>) => {
      if (!triggered) {
        triggered = true
        cancelPromise = reader.cancel()
        throw new Error('simulated db error mid-flush after cancel')
      }
      return origEventsAfter(...args)
    }) as typeof db.eventsAfter

    try {
      db.event(run.id, 'run.note', 'trigger-2')
      await cancelPromise
    } finally {
      db.eventsAfter = origEventsAfter
    }
    ac.abort()
  }

  await new Promise((r) => setTimeout(r, 20))
  assert.deepEqual(unhandled, [])
})
