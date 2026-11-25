import { expect, test } from '@playwright/test'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { createApp } from './app.ts'
import { Store } from '../src/server/store.ts'

test.setTimeout(90_000)

const origin = 'https://board-e2e.example'

test('renders the mandatory Board tab with seeded roster, messages, evidence chips, approvals, and routes the composer', async ({ page }) => {
  const directory = mkdtempSync(join(tmpdir(), 'kovo-v5-board-e2e-'))
  const store = new Store(directory)
  const { id: projectId } = store.createProject({
    requestId: randomUUID(), name: 'Board E2E', seeds: [origin], environment: 'public',
  })
  const { id: runId } = store.createRun({
    requestId: randomUUID(), projectId, goal: 'Render the swarm message board.',
    sourceMode: 'public', capabilityTier: 3, approvalPolicy: 'strict',
    budgetUsd: 5, budgetRequests: 200, maxRpsPerOrigin: 30, workerConcurrency: 2, workerMaxTurns: 20,
  })
  const run = store.run(runId)
  const candidate = { id: randomUUID(), origin, source: 'Fixture inventory', thirdParty: false }
  store.client.prepare('UPDATE runs SET phase = ?, status = ?, candidates = ?, approved = ?, scope_revision = ? WHERE id = ?')
    .run('investigation', 'paused', JSON.stringify([candidate]), JSON.stringify([candidate.id]), 1, runId)

  const assignmentId = randomUUID()
  store.client.prepare(
    `INSERT INTO assignments (id, run_id, phase, status, scope_revision, goal_revision, session_id, parent_fact_ids, source_origins, title, objective, created_at)
     VALUES (?, ?, 'investigation', 'running', 1, 0, ?, '[]', ?, 'BOLA specialist', 'Probe tenant isolation.', ?)`,
  ).run(assignmentId, runId, randomUUID(), JSON.stringify([origin]), Date.now())
  const assignment = store.worker(assignmentId)
  const fact = store.addFact(store.run(runId), assignment, {
    kind: 'persona_resource', origin, summary: 'Invoice 42 belongs to persona user_a.', data: { resourceId: '42', ownerPersona: 'user_a' },
  })

  store.upsertBoardMember(runId, {
    handle: 'bola', role: 'specialist', specialistProfile: 'bola-bfla-specialist',
    state: 'working', activeAssignmentId: assignmentId, sourceOrigins: [origin],
  })
  store.upsertBoardMember(runId, {
    handle: 'auth', role: 'specialist', specialistProfile: 'auth-session-oauth-specialist',
    state: 'waiting', sourceOrigins: [origin],
  })
  store.postBoardMessage(runId, {
    authorHandle: 'coordinator', authorRole: 'coordinator', kind: 'brief',
    body: 'Map tenant isolation on the invoices API.', mentions: ['bola'], refStepId: null,
  })
  store.postBoardMessage(runId, {
    authorHandle: 'bola', authorRole: 'specialist', kind: 'handoff',
    body: 'Cross-tenant token mint observed. Test the stored payload render.', mentions: ['injection'], refFactIds: [fact.id],
  })
  store.postBoardMessage(runId, {
    authorHandle: 'verifier', authorRole: 'verifier', kind: 'verdict', body: 'Replay spec failed the control check.',
  })
  store.postBoardMessage(runId, {
    authorHandle: 'broker', authorRole: 'system', kind: 'blocker', body: 'Origin circuit opened after repeated 429s.', mentions: ['all'],
  })

  const approvalId = randomUUID()
  store.client.prepare(
    `INSERT INTO approval_requests (id, run_id, assignment_id, scope_revision, origin, method, path_and_query,
       rationale, request_preview, status, expires_at, created_at)
     VALUES (?, ?, ?, 1, ?, 'POST', '/api/invoices/42', ?, 'POST /api/invoices/42', 'pending', ?, ?)`,
  ).run(approvalId, runId, assignmentId, origin, 'State-changing invoice update probe.', Date.now() + 60_000, Date.now())
  store.postBoardMessage(runId, {
    authorHandle: 'broker', authorRole: 'system', kind: 'approval',
    body: 'Tier 3 approval required for the state-changing probe.', refApprovalId: approvalId,
  })
  store.close()

  const app = await createApp({}, directory)
  try {
    await app.start()
    await app.open(page)
    await page.goto(`${app.url}/runs/${runId}?view=overview`)

    // Mandatory right-pane swap: Board replaces Coordinator, Worker Inspector remains available.
    const boardTab = page.getByRole('button', { name: /^Board/ })
    await expect(boardTab).toBeVisible({ timeout: 20_000 })
    await expect(page.getByRole('button', { name: 'Coordinator', exact: true })).toHaveCount(0)
    await expect(page.getByTestId('board-pane')).toBeVisible()

    // Roster strip: system actors + spawned specialist with live state pills.
    const roster = page.getByTestId('board-roster')
    await expect(roster).toContainText('@coordinator')
    await expect(roster).toContainText('@bola')
    await expect(roster.locator('[data-handle=bola]')).toHaveAttribute('data-state', 'working')
    await expect(roster.locator('[data-handle=auth]')).toHaveAttribute('data-state', 'waiting')

    // Timeline: seeded briefs/handoffs/verdicts/blockers with kind pills.
    const timeline = page.getByTestId('board-timeline')
    await expect(timeline).toContainText('Map tenant isolation on the invoices API.')
    await expect(timeline).toContainText('Cross-tenant token mint observed.')
    await expect(timeline.locator('[data-kind=brief]').first()).toContainText('BRIEF')
    await expect(timeline.locator('[data-kind=verdict]').first()).toContainText('VERDICT')

    // Inline Tier 3 approval card synced via refApprovalId.
    const approvals = page.getByTestId('board-approvals')
    await expect(approvals).toContainText('Tier 3 approval')
    await expect(approvals).toContainText('/api/invoices/42')
    await expect(approvals.getByRole('button', { name: 'Approve', exact: true })).toBeVisible()
    await expect(page.getByTestId('board-approval-inline')).toContainText('Tier 3 approval')

    // Clickable evidence chip opens the referenced fact.
    const chip = timeline.locator(`[data-ref-kind=fact][data-ref-id="${fact.id}"]`)
    await expect(chip).toBeVisible()
    await chip.click()
    await expect(page.getByTestId('board-ref-detail')).toContainText('Invoice 42 belongs to persona user_a.')

    // Filters: Blockers hide the brief, All restores it.
    await page.getByRole('button', { name: 'Blockers', exact: true }).click()
    await expect(timeline).toContainText('Origin circuit opened after repeated 429s.')
    await expect(timeline).not.toContainText('Map tenant isolation on the invoices API.')
    await page.getByRole('button', { name: 'All', exact: true }).click()
    await expect(timeline).toContainText('Map tenant isolation on the invoices API.')

    // Plain composer text defaults to @coordinator through the legacy message action.
    const composer = page.getByLabel('Message board')
    await composer.fill('Steer toward the admin surface.')
    await composer.press('Enter')
    await expect(timeline).toContainText('Steer toward the admin surface.', { timeout: 20_000 })
    await expect(timeline.locator('[data-role=operator]').last()).toContainText('NOTE')

    // @mention autocomplete lists active roster handles and submits a public board_post.
    await composer.fill('@bo')
    const option = page.getByRole('option', { name: /@bola/ })
    await expect(option).toBeVisible()
    await composer.press('Enter')
    await expect(composer).toHaveValue(/@bola /)
    await composer.pressSequentially('check invoice IDOR')
    await composer.press('Enter')
    await expect(timeline).toContainText('@bola check invoice IDOR', { timeout: 20_000 })
    await expect(timeline.locator('[data-role=operator]').last()).toContainText('HANDOFF')
  } finally {
    await app.dispose()
    rmSync(directory, { recursive: true, force: true })
  }
})
