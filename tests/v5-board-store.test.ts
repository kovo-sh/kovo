/**
 * Kovo Hunter v5 M5 Phase 1 — Swarm Message Board schema & store suite.
 *
 * Covers: lossless v2–v4 → v5 auto-migration, roster seeding/upsert, IMMEDIATE seq
 * allocation, mention parsing/validation, filters, runDetail hydration, and operator
 * command routing (`message` mirror, `board_post`, `retire_member`).
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { DatabaseSync } from 'node:sqlite'
import { test } from 'node:test'
import { runCommand } from '../src/domain.ts'
import { Store } from '../src/server/store.ts'

const originA = 'https://board-a.example'
const originB = 'https://board-b.example'

function makeStore(t: { after: (fn: () => void) => void }) {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-v5-board-store-'))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  const store = new Store(dir)
  t.after(() => store.close())
  const { id: projectId } = store.createProject({
    requestId: randomUUID(), name: 'Board store', seeds: [originA], environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(), projectId, goal: 'Exercise the swarm board.',
    sourceMode: 'public', capabilityTier: 2, budgetUsd: 5, budgetRequests: 200,
    maxRpsPerOrigin: 30, workerConcurrency: 2, workerMaxTurns: 20,
  })
  return { dir, store, projectId, runId }
}

test('v5 board schema auto-migrates a v4 database without losing rows and re-creates board tables', t => {
  const { dir, store, runId } = makeStore(t)
  store.message(runId, store.run(runId).coordinatorId, 'operator', 'Legacy coordinator question')
  store.close()

  const raw = new DatabaseSync(join(dir, 'kovo.sqlite'))
  raw.exec('DROP TABLE board_messages; DROP TABLE board_members;')
  const beforeRuns = (raw.prepare('SELECT COUNT(*) AS c FROM runs').get() as { c: number }).c
  const beforeMessages = (raw.prepare('SELECT COUNT(*) AS c FROM messages').get() as { c: number }).c
  raw.close()

  const reopened = new Store(dir)
  t.after(() => reopened.close())
  const tables = reopened.client.prepare("SELECT name FROM sqlite_master WHERE type = 'table'").all() as Array<{ name: string }>
  const names = new Set(tables.map(row => row.name))
  assert.ok(names.has('board_members'))
  assert.ok(names.has('board_messages'))

  const memberColumns = new Set((reopened.client.prepare('PRAGMA table_info(board_members)').all() as Array<{ name: string }>).map(row => row.name))
  for (const column of ['scope_revision', 'goal_revision', 'source_origins', 'last_read_seq', 'peer_hops_used', 'state']) {
    assert.ok(memberColumns.has(column), `board_members.${column}`)
  }
  const messageColumns = new Set((reopened.client.prepare('PRAGMA table_info(board_messages)').all() as Array<{ name: string }>).map(row => row.name))
  for (const column of [
    'seq', 'author_handle', 'author_role', 'kind', 'mentions', 'body', 'ref_fact_ids',
    'ref_exchange_ids', 'ref_finding_ids', 'ref_step_id', 'ref_approval_id', 'reply_to_seq',
    'scope_revision', 'goal_revision', 'source_origins', 'tainted',
  ]) {
    assert.ok(messageColumns.has(column), `board_messages.${column}`)
  }
  assert.equal((reopened.client.prepare('SELECT COUNT(*) AS c FROM runs').get() as { c: number }).c, beforeRuns)
  assert.equal((reopened.client.prepare('SELECT COUNT(*) AS c FROM messages').get() as { c: number }).c, beforeMessages)
  assert.ok(reopened.listBoardMembers(runId).some(member => member.handle === 'coordinator'))
})

test('v5 board roster seeds system actors and supports upsert/update/list of sharded specialists', t => {
  const { store, runId } = makeStore(t)
  const seeded = store.listBoardMembers(runId)
  assert.deepEqual(seeded.map(member => member.handle).sort(), ['broker', 'canary', 'coordinator', 'verifier'])
  assert.equal(seeded.find(member => member.handle === 'coordinator')?.state, 'waiting')

  const specialist = store.upsertBoardMember(runId, {
    handle: 'bola-2',
    role: 'specialist',
    specialistProfile: 'bola-bfla-specialist',
    state: 'working',
    activeAssignmentId: 'assignment-1',
    sourceOrigins: [originA],
    roleAffinity: 'reasoning',
  })
  assert.equal(specialist.handle, 'bola-2')
  assert.equal(specialist.state, 'working')
  assert.equal(specialist.scopeRevision, 0)

  const updated = store.updateBoardMemberState(runId, '@bola-2', { state: 'waiting', lastReadSeq: 7, turnsUsed: 2 })
  assert.equal(updated.state, 'waiting')
  assert.equal(updated.lastReadSeq, 7)
  assert.equal(updated.turnsUsed, 2)
  assert.equal(updated.postsCount, 0)
  assert.equal(store.listBoardMembers(runId).length, 5)
  assert.throws(() => store.upsertBoardMember(runId, { handle: 'Bad Handle', role: 'specialist' }), /handle/i)
})

test('v5 postBoardMessage allocates strictly monotonic per-run seq and hydrates into runDetail', t => {
  const { store, runId, projectId } = makeStore(t)
  const other = store.createRun({
    requestId: randomUUID(), projectId, goal: 'Second run.', sourceMode: 'public',
    capabilityTier: 2, budgetUsd: 5, budgetRequests: 100, maxRpsPerOrigin: 10,
    workerConcurrency: 1, workerMaxTurns: 10,
  })
  const first = store.postBoardMessage(runId, {
    authorHandle: 'coordinator', authorRole: 'coordinator', kind: 'brief', body: 'Start with the auth surface.',
  })
  const second = store.postBoardMessage(runId, {
    authorHandle: 'verifier', authorRole: 'verifier', kind: 'verdict', body: 'Replay spec failed the control check.',
  })
  const otherFirst = store.postBoardMessage(other.id, {
    authorHandle: 'coordinator', authorRole: 'coordinator', kind: 'brief', body: 'Independent run.',
  })
  assert.deepEqual([first.seq, second.seq], [1, 2])
  assert.equal(otherFirst.seq, 1)
  assert.equal(first.scopeRevision, store.run(runId).scopeRevision)
  assert.equal(first.goalRevision, store.run(runId).goalRevision)
  assert.equal(first.tainted, false)

  const detail = store.runDetail(runId)
  assert.equal(detail.boardMembers.length, 4)
  assert.deepEqual(detail.boardMessages.map(message => message.seq), [1, 2])
  assert.equal(detail.boardMessages[0].body, 'Start with the auth surface.')
})

test('v5 postBoardMessage parses and validates mentions, defaults evidence-free bodies, and blocks @all abuse', t => {
  const { store, runId } = makeStore(t)
  const parsed = store.postBoardMessage(runId, {
    authorHandle: 'operator', authorRole: 'operator', kind: 'handoff',
    body: 'Please verify the JWT flow @coordinator and @bola — cc user@example.com',
  })
  assert.deepEqual(parsed.mentions, ['coordinator', 'bola'])

  assert.throws(() => store.postBoardMessage(runId, {
    authorHandle: 'operator', authorRole: 'operator', kind: 'note', body: 'probe @doesnotexist',
  }), /unknown or retired/i)

  assert.throws(() => store.postBoardMessage(runId, {
    authorHandle: 'bola', authorRole: 'specialist', kind: 'blocker', body: 'Circuit open @all',
    sourceOrigins: [],
  }), /@all/i)

  const broadcast = store.postBoardMessage(runId, {
    authorHandle: 'coordinator', authorRole: 'coordinator', kind: 'blocker', body: 'Rate limit reached @all',
  })
  assert.deepEqual(broadcast.mentions, ['all'])

  assert.throws(() => store.postBoardMessage(runId, {
    authorHandle: 'operator', authorRole: 'operator', kind: 'note', body: 'Bad reply', replyToSeq: 99,
  }), /does not exist/i)
})

test('v5 listBoardMessages filters by sinceSeq, author, kind, mention, taint visibility and limit', t => {
  const { store, runId } = makeStore(t)
  const brief = store.postBoardMessage(runId, {
    authorHandle: 'coordinator', authorRole: 'coordinator', kind: 'brief', body: 'Brief @bola',
  })
  store.postBoardMessage(runId, {
    authorHandle: 'bola', authorRole: 'specialist', kind: 'handoff', body: 'Handoff @auth',
  })
  store.postBoardMessage(runId, { authorHandle: 'verifier', authorRole: 'verifier', kind: 'verdict', body: 'Verdict.' })

  assert.deepEqual(store.listBoardMessages(runId, { sinceSeq: brief.seq }).map(message => message.seq), [2, 3])
  assert.equal(store.listBoardMessages(runId, { authorHandle: 'verifier' }).length, 1)
  assert.equal(store.listBoardMessages(runId, { kind: 'handoff' }).length, 1)
  assert.equal(store.listBoardMessages(runId, { mentionHandle: '@bola' }).length, 1)
  assert.equal(store.listBoardMessages(runId, { limit: 2 }).length, 2)
  assert.equal(store.listBoardMessages(runId, { includeTainted: false }).length, 3)
  assert.equal(store.postBoardMessage(runId, { authorHandle: 'operator', authorRole: 'operator', kind: 'note', body: 'noise' }).seq, 4)
})

test('v5 runCommand routes plain messages to @coordinator and mirrors into legacy messages', t => {
  const { store, runId } = makeStore(t)
  const before = store.runDetail(runId).messages.length
  store.command({
    requestId: randomUUID(), runId, action: 'message', message: 'Focus on tenant isolation next.',
  })
  const detail = store.runDetail(runId)
  const boardPost = detail.boardMessages.at(-1)!
  assert.equal(boardPost.authorHandle, 'operator')
  assert.equal(boardPost.authorRole, 'operator')
  assert.deepEqual(boardPost.mentions, ['coordinator'])
  assert.equal(boardPost.kind, 'note')
  assert.ok(detail.messages.length > before)
  assert.equal(detail.messages.at(-2)?.role, 'operator')
  assert.match(detail.messages.at(-2)?.content ?? '', /tenant isolation/)
})

test('v5 runCommand board_post honours explicit mentions and retire_member retires the roster row', t => {
  const { store, runId } = makeStore(t)
  store.upsertBoardMember(runId, {
    handle: 'injection', role: 'specialist', specialistProfile: 'injection-parser-specialist',
    state: 'working', sourceOrigins: [originA],
  })
  store.command({
    requestId: randomUUID(), runId, action: 'board_post',
    body: 'Check the stored payload render @injection', mentions: ['injection'], kind: 'handoff',
  })
  const posted = store.runDetail(runId).boardMessages.at(-1)!
  assert.deepEqual(posted.mentions, ['injection'])
  assert.equal(posted.kind, 'handoff')

  store.command({ requestId: randomUUID(), runId, action: 'retire_member', handle: '@injection' })
  assert.equal(store.boardMember(runId, 'injection')?.state, 'retired')
  assert.throws(() => store.command({ requestId: randomUUID(), runId, action: 'retire_member', handle: 'coordinator' }), /cannot be retired/i)
})

test('v5 board_post command schema normalizes handles and caps body length', () => {
  const base = { requestId: randomUUID(), runId: randomUUID(), action: 'board_post' as const }
  const parsed = runCommand.safeParse({ ...base, body: 'Ping @Bola', mentions: ['@BOLA'] })
  assert.equal(parsed.success, true)
  if (parsed.success && parsed.data.action === 'board_post') {
    assert.deepEqual(parsed.data.mentions, ['bola'])
  }
  assert.equal(runCommand.safeParse({ ...base, body: 'x'.repeat(1201) }).success, false)
  assert.equal(runCommand.safeParse({ ...base, body: 'ok', mentions: ['not a handle'] }).success, false)
})
