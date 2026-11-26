import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import ts from 'typescript'
import { newRun, runCommand } from '../src/domain.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function makeStore(t: { after(fn: () => void): void }): Store {
  const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-leases-rename-'))
  const store = new Store(dir)
  t.after(() => {
    try { store.close() } catch { /* already closed */ }
    rmSync(dir, { recursive: true, force: true })
  })
  return store
}

function setupTier3Run(store: Store) {
  const project = store.createProject({
    requestId: randomUUID(),
    name: `Leases & Rename ${randomUUID().slice(0, 6)}`,
    seeds: ['https://app.example.test'],
    environment: 'public',
  })
  const { id: runId } = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify active approval leases, scope policy switching, and non-destructive rename',
    sourceMode: 'public',
    capabilityTier: 3,
    approvalPolicy: 'auto_review',
    budgetUsd: 25,
    budgetRequests: 2000,
    maxRpsPerOrigin: 5,
  }))
  store.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = store.run(runId)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
    capabilityTier: 3,
    approvalPolicy: 'auto_review',
  }))
  store.updateRun(runId, { phase: 'investigation', status: 'running' })
  return { projectId: project.id, runId, run: store.run(runId) }
}

function loadExportedTsxFn<T extends (...args: never[]) => unknown>(
  relPath: string,
  fnName: string,
  scopeVars: Record<string, unknown> = {},
): T {
  const fullPath = join(REPO_ROOT, relPath)
  const src = readFileSync(fullPath, 'utf8')
  const sf = ts.createSourceFile(fullPath, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX)
  let fnText: string | null = null
  for (const stmt of sf.statements) {
    if (ts.isFunctionDeclaration(stmt) && stmt.name?.text === fnName) {
      fnText = src.slice(stmt.getStart(sf), stmt.getEnd())
      break
    }
  }
  assert.ok(fnText, `Expected exported function ${fnName} in ${relPath}`)
  const cleaned = fnText.replace(/^export\s+/, '')
  const js = ts.transpileModule(cleaned, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText
  const keys = Object.keys(scopeVars)
  const vals = Object.values(scopeVars)
  const factory = new Function(...keys, `${js}\nreturn ${fnName};`)
  return factory(...vals) as T
}

test('runDetail exposes active approvalLeases + approvedEndpointPatterns, and revoke_approval_lease / remove_approved_pattern revoke them', t => {
  const store = makeStore(t)
  const { runId, run } = setupTier3Run(store)
  const worker = store.makeWorker(run, 'investigation', run.candidates[0]!, 'Write test', 'Probe POST /api/items/42')

  // Seed a pending approval and approve it with similar endpoint pattern (creates BOTH pattern and durable lease)
  const req1 = store.createApprovalRequest(run, worker, {
    origin: 'https://app.example.test',
    method: 'POST',
    pathAndQuery: '/api/items/42',
    requestPreview: '{"name":"test"}',
    rationale: 'Mutation probe',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'approve_similar_endpoint',
    approvalId: req1.id,
  }))

  // Seed a second standalone durable lease + an expired lease
  const directLease = store.runsRepo.grantApprovalLease(store.run(runId), {
    origin: 'https://app.example.test',
    method: 'PATCH',
    pathAndQuery: '/api/settings/profile',
    createdBy: 'operator',
    expiresInMs: 60_000,
  })
  store.runsRepo.grantApprovalLease(store.run(runId), {
    origin: 'https://app.example.test',
    method: 'DELETE',
    pathAndQuery: '/api/items/99',
    createdBy: 'operator',
    expiresInMs: -1_000,
  })

  const detail = store.runDetail(runId)
  assert.equal(detail.approvalLeases.length, 2, 'only active unexpired leases in current scopeRevision appear')
  assert.equal(detail.approvedEndpointPatterns.length, 1)
  assert.equal(store.runsRepo.leaseAuthorizes(runId, 'https://app.example.test', 'POST', '/api/items/99'), true)
  assert.equal(store.runsRepo.leaseAuthorizes(runId, 'https://app.example.test', 'PATCH', '/api/settings/profile'), true)

  // Revoke the lease created via approve_similar_endpoint -> must revoke lease AND remove matching approvedEndpointPattern
  const patternLease = detail.approvalLeases.find(l => l.method === 'POST')!
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'revoke_approval_lease',
    leaseId: patternLease.id,
  }))

  const afterRevoke = store.runDetail(runId)
  assert.equal(afterRevoke.approvalLeases.length, 1)
  assert.equal(afterRevoke.approvalLeases[0]!.id, directLease.id)
  assert.equal(afterRevoke.approvedEndpointPatterns.length, 0)
  assert.equal(store.runsRepo.leaseAuthorizes(runId, 'https://app.example.test', 'POST', '/api/items/99'), false)

  // Add a pattern-only entry and remove it via remove_approved_pattern
  const req2 = store.createApprovalRequest(store.run(runId), worker, {
    origin: 'https://app.example.test',
    method: 'PUT',
    pathAndQuery: '/api/orders/10',
    requestPreview: '{"qty":2}',
    rationale: 'Order update probe',
  })
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'approve_similar_endpoint',
    approvalId: req2.id,
  }))
  const withPutPattern = store.runDetail(runId)
  assert.equal(withPutPattern.approvedEndpointPatterns.length, 1)
  assert.equal(withPutPattern.approvedEndpointPatterns[0]!.pathPattern, '/api/orders/*')

  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'remove_approved_pattern',
    origin: 'https://app.example.test',
    method: 'PUT',
    pathPattern: withPutPattern.approvedEndpointPatterns[0]!.pathPattern,
  }))

  const afterPatternRemove = store.runDetail(runId)
  assert.equal(afterPatternRemove.approvedEndpointPatterns.length, 0)
  assert.equal(afterPatternRemove.approvalLeases.length, 1, 'PATCH direct lease remains active')
  assert.equal(store.runsRepo.leaseAuthorizes(runId, 'https://app.example.test', 'PUT', '/api/orders/11'), false)
})

test('ScopeOverlay scopeCommand preserves approvalPolicy when scopeOnly is true and updates run approvalPolicy', t => {
  type ScopeCommandFn = (
    r: { scopeRevision: number },
    d: {
      assetIds: string[]
      capabilityTier: 0 | 1 | 2 | 3
      approvalPolicy: 'auto_review' | 'yolo' | 'strict'
      approvedPersonaIds: string[]
      budgetUsd: number
      budgetRequests: number
      maxRpsPerOrigin: number
    },
    opts?: { saveProject?: boolean; scopeOnly?: boolean; expectedScopeRevision?: number },
  ) => Record<string, unknown>

  const scopeCommand = loadExportedTsxFn<ScopeCommandFn>(
    'src/components/run/views/consent.tsx',
    'scopeCommand',
  )

  const cmdYolo = scopeCommand(
    { scopeRevision: 1 },
    {
      assetIds: ['a-1'],
      capabilityTier: 3,
      approvalPolicy: 'yolo',
      approvedPersonaIds: [],
      budgetUsd: 25,
      budgetRequests: 0,
      maxRpsPerOrigin: 5,
    },
    { scopeOnly: true, expectedScopeRevision: 1 },
  )
  assert.equal(cmdYolo.action, 'scope')
  assert.equal(cmdYolo.approvalPolicy, 'yolo', 'scopeOnly must NOT drop approvalPolicy')
  assert.equal('budgetUsd' in cmdYolo, false, 'scopeOnly still omits budget fields')

  const cmdSupervised = scopeCommand(
    { scopeRevision: 2 },
    {
      assetIds: ['a-1'],
      capabilityTier: 3,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: [],
      budgetUsd: 25,
      budgetRequests: 0,
      maxRpsPerOrigin: 5,
    },
    { scopeOnly: true, expectedScopeRevision: 2 },
  )
  assert.equal(cmdSupervised.approvalPolicy, 'auto_review')

  // End-to-end verification in Store: scope command updates approvalPolicy live
  const store = makeStore(t)
  const { runId, run } = setupTier3Run(store)
  assert.equal(run.approvalPolicy, 'auto_review')

  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    ...cmdYolo,
    assetIds: run.approved,
    expectedScopeRevision: run.scopeRevision,
  }))
  assert.equal(store.run(runId).approvalPolicy, 'yolo')

  const updated = store.run(runId)
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    ...cmdSupervised,
    assetIds: updated.approved,
    expectedScopeRevision: updated.scopeRevision,
  }))
  assert.equal(store.run(runId).approvalPolicy, 'auto_review')
})

test('rename_run adds label column if absent and renames display label non-destructively without bumping goalRevision or canceling workers', t => {
  const store = makeStore(t)
  const { projectId, runId, run } = setupTier3Run(store)
  const activeWorker = store.makeWorker(run, 'investigation', run.candidates[0]!, 'Active worker', 'Keep running')
  store.updateWorker(activeWorker.id, { status: 'running', lease: randomUUID() })

  const initialGoal = run.goal
  const initialGoalRevision = run.goalRevision
  const initialScopeRevision = run.scopeRevision
  assert.equal(run.label, null)

  // Rename run via runCommand
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'rename_run',
    label: 'Q4 Staging Auth Regression',
  }))

  const renamed = store.run(runId)
  assert.equal(renamed.label, 'Q4 Staging Auth Regression')
  assert.equal(renamed.goal, initialGoal, 'rename_run must not overwrite original/current goal')
  assert.equal(renamed.goalRevision, initialGoalRevision, 'rename_run must NOT increment goalRevision')
  assert.equal(renamed.scopeRevision, initialScopeRevision, 'rename_run must NOT increment scopeRevision')
  assert.equal(renamed.status, 'running')
  assert.equal(store.worker(activeWorker.id).status, 'running', 'rename_run must NOT cancel active workers')

  // runDetail & listProjectRunLabels reflect the label
  assert.equal(store.runDetail(runId).run.label, 'Q4 Staging Auth Regression')
  assert.deepEqual(store.runsRepo.listProjectRunLabels(projectId), {
    [runId]: 'Q4 Staging Auth Regression',
  })

  // Clearing with blank string resets label to null
  store.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'rename_run',
    label: '   ',
  }))
  assert.equal(store.run(runId).label, null)
  assert.deepEqual(store.runsRepo.listProjectRunLabels(projectId), {})
})

test('UI components wire Leases popover, inline RunHeader rename, ProjectOverviewTab label + Re-run, and Board retire_member', () => {
  const headerSrc = readFileSync(join(REPO_ROOT, 'src/components/run/header.tsx'), 'utf8')
  assert.match(headerSrc, /function LeasesPopover\(/, 'RunHeader must define LeasesPopover')
  assert.match(headerSrc, /function LeasesList\(/, 'RunHeader must define LeasesList')
  assert.match(headerSrc, /revoke_approval_lease/, 'Leases UI must invoke revoke_approval_lease')
  assert.match(headerSrc, /extend_approval_lease/, 'Leases UI must invoke extend_approval_lease')
  assert.match(headerSrc, /rename_run/, 'RunHeader must invoke rename_run for inline run renaming')
  assert.match(headerSrc, /aria-label="Run label"/, 'RunHeader inline rename input must have accessible label')
  assert.match(headerSrc, /r\.label \|\| r\.goal/, 'RunHeader must render r.label || r.goal')

  const coordinatorSrc = readFileSync(join(REPO_ROOT, 'src/components/run/coordinator.tsx'), 'utf8')
  assert.match(coordinatorSrc, /m\.role !== 'coordinator' && m\.role !== 'system' && m\.state !== 'retired'/)
  assert.match(coordinatorSrc, /action:\s*'retire_member'/, 'AgentsDropdown must invoke retire_member')
  assert.match(coordinatorSrc, />\s*Retire\s*<\/button>/, 'AgentsDropdown must render Retire button')

  const overviewSrc = readFileSync(join(REPO_ROOT, 'src/components/project/ProjectOverviewTab.tsx'), 'utf8')
  assert.match(overviewSrc, /listProjectRunLabelsAction/, 'ProjectOverviewTab must load project run labels')
  assert.match(overviewSrc, /run\.status === 'complete'/, 'ProjectOverviewTab must render Re-run on completed runs')
  assert.match(overviewSrc, /Re-run/, 'ProjectOverviewTab must include Re-run action label')
  assert.match(overviewSrc, /getRunRerunPresetAction/, 'ProjectOverviewTab Re-run must reuse completed run settings')

  const actionsSrc = readFileSync(join(REPO_ROOT, 'src/actions-run-controls.ts'), 'utf8')
  assert.match(actionsSrc, /export const revokeApprovalLeaseAction/)
  assert.match(actionsSrc, /export const removeApprovedPatternAction/)
  assert.match(actionsSrc, /export const renameRunAction/)
  assert.match(actionsSrc, /export const listProjectRunLabelsAction/)
  assert.match(actionsSrc, /export const getRunRerunPresetAction/)
})
