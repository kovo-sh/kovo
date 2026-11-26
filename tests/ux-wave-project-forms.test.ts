import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import ts from 'typescript'
import { newRun } from '../src/domain.ts'
import * as tables from '../src/server/schema.ts'
import { Store } from '../src/server/store.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

function readSrc(relPath: string): string {
  return readFileSync(join(REPO_ROOT, relPath), 'utf8')
}

function evalExportedFunction<T>(relPath: string, fnName: string): T {
  const src = readSrc(relPath)
  const sf = ts.createSourceFile(relPath, src, ts.ScriptTarget.ES2022, true, ts.ScriptKind.TSX)
  const decl = sf.statements.find(
    (stmt): stmt is ts.FunctionDeclaration => ts.isFunctionDeclaration(stmt) && stmt.name?.text === fnName,
  )
  assert.ok(decl, `Expected export function ${fnName} in ${relPath}`)
  const snippet = src.slice(decl.getStart(sf), decl.end).replace(/^export\s+/, '')
  const js = ts.transpileModule(snippet, {
    compilerOptions: { target: ts.ScriptTarget.ES2022, module: ts.ModuleKind.ESNext },
  }).outputText
  return new Function(`${js}\nreturn ${fnName};`)() as T
}

function withTempStore(fn: (ctx: { dir: string; store: Store }) => Promise<void> | void) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-proj-forms-'))
    const store = new Store(dir, { ftsMode: 'preview' })
    try {
      await fn({ dir, store })
    } finally {
      store.close()
      rmSync(dir, { recursive: true, force: true })
    }
  }
}

test('A8: createProject seeds defaultScope with validatedSeeds, supports reversible scope toggle, and deleteProjectAsset cleans up', withTempStore(({ store }) => {
  const created = store.createProject({
    requestId: randomUUID(),
    name: 'Northstar App',
    seeds: ['https://app.northstar.example', 'https://api.northstar.example'],
    environment: 'public',
    includeSubdomains: true,
  })

  // Seeds start approved in project.defaultScope
  const initial = store.projectDetail(created.id)
  assert.deepEqual(
    [...initial.project.defaultScope].sort(),
    ['https://api.northstar.example', 'https://app.northstar.example'],
  )
  assert.equal(initial.assets.length, 2)

  // Reversible approve toggle works on first-party seed asset
  const apiAsset = initial.assets.find(a => a.origin === 'https://api.northstar.example')!
  const unapproved = store.updateProjectAssetScope({
    requestId: randomUUID(),
    projectId: created.id,
    assetId: apiAsset.id,
    approveInDefaultScope: false,
  })
  assert.equal(unapproved.approvedInDefaultScope, false)
  assert.deepEqual(store.project(created.id).defaultScope, ['https://app.northstar.example'])

  const reapproved = store.updateProjectAssetScope({
    requestId: randomUUID(),
    projectId: created.id,
    assetId: apiAsset.id,
    approveInDefaultScope: true,
  })
  assert.equal(reapproved.approvedInDefaultScope, true)
  assert.deepEqual(
    [...store.project(created.id).defaultScope].sort(),
    ['https://api.northstar.example', 'https://app.northstar.example'],
  )

  // Manually added third-party host starts unapproved, can be approved/unapproved and deleted cleanly
  const added = store.addProjectAsset({
    requestId: randomUUID(),
    projectId: created.id,
    origin: 'https://docs.northstar.example',
    source: 'Manual entry',
    thirdParty: true,
  })
  assert.equal(store.project(created.id).defaultScope.includes('https://docs.northstar.example'), false)

  store.updateProjectAssetScope({
    requestId: randomUUID(),
    projectId: created.id,
    assetId: added.id,
    approveInDefaultScope: true,
  })
  assert.equal(store.project(created.id).defaultScope.includes('https://docs.northstar.example'), true)

  const deleteReqId = randomUUID()
  const deleted = store.projectsRepo.deleteProjectAsset({
    requestId: deleteReqId,
    projectId: created.id,
    assetId: added.id,
  })
  assert.deepEqual(deleted, { id: added.id, origin: 'https://docs.northstar.example' })

  // Idempotent replay with same requestId returns cached result
  const deletedReplay = store.projectsRepo.deleteProjectAsset({
    requestId: deleteReqId,
    projectId: created.id,
    assetId: added.id,
  })
  assert.deepEqual(deletedReplay, deleted)

  // Deleted asset removed from project_assets and defaultScope
  const afterDelete = store.projectDetail(created.id)
  assert.equal(afterDelete.assets.some(a => a.id === added.id), false)
  assert.equal(afterDelete.project.defaultScope.includes('https://docs.northstar.example'), false)

  // Deleting a seed asset also cleans up project.seeds and defaultScope
  store.projectsRepo.deleteProjectAsset({
    requestId: randomUUID(),
    projectId: created.id,
    assetId: apiAsset.id,
  })
  const afterSeedDelete = store.projectDetail(created.id)
  assert.deepEqual(afterSeedDelete.project.seeds, ['https://app.northstar.example'])
  assert.deepEqual(afterSeedDelete.project.defaultScope, ['https://app.northstar.example'])

  // Deleting a nonexistent asset throws
  assert.throws(
    () => store.projectsRepo.deleteProjectAsset({
      requestId: randomUUID(),
      projectId: created.id,
      assetId: randomUUID(),
    }),
    /Project asset not found/,
  )
}))

test('C: projectDetail computes isActive accurately for running runs, waiting_approval workers, and running lab containers', withTempStore(({ store }) => {
  const proj = store.createProject({
    requestId: randomUUID(),
    name: 'Active Guard Project',
    seeds: ['https://guard.example'],
    environment: 'public',
  })

  const idleRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: 'Idle run',
    capabilityTier: 1,
  }))
  const runningRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: 'Running run',
    capabilityTier: 1,
  }))
  const approvalWorkerRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: 'Paused run with waiting_approval worker',
    capabilityTier: 3,
  }))
  const labContainerRun = store.createRun(newRun.parse({
    requestId: randomUUID(),
    projectId: proj.id,
    goal: 'Stopped run with running lab container',
    capabilityTier: 2,
  }))

  store.client.prepare(`UPDATE runs SET status = 'complete' WHERE id = ?`).run(idleRun.id)
  store.client.prepare(`UPDATE runs SET status = 'running', phase = 'investigation' WHERE id = ?`).run(runningRun.id)
  store.client.prepare(`UPDATE runs SET status = 'paused', phase = 'investigation' WHERE id = ?`).run(approvalWorkerRun.id)
  store.db.insert(tables.assignments).values({
    id: randomUUID(),
    runId: approvalWorkerRun.id,
    phase: 'investigation',
    status: 'waiting_approval',
    scopeRevision: 1,
    goalRevision: 1,
    sessionId: `sess-${randomUUID()}`,
    parentFactIds: [],
    sourceOrigins: ['https://guard.example'],
    title: 'Pending approval worker',
    objective: 'Wait for operator',
    createdAt: Date.now(),
  }).run()

  store.client.prepare(`UPDATE runs SET status = 'paused', phase = 'investigation' WHERE id = ?`).run(labContainerRun.id)
  store.db.insert(tables.labContainers).values({
    id: randomUUID(),
    runId: labContainerRun.id,
    containerName: `lab-${randomUUID()}`,
    status: 'running',
    createdAt: Date.now(),
    updatedAt: Date.now(),
  }).run()

  const detail = store.projectDetail(proj.id)
  const byId = new Map(detail.runs.map(r => [r.id, r]))
  assert.equal(byId.get(idleRun.id)?.isActive, false)
  assert.equal(byId.get(runningRun.id)?.isActive, true)
  // R3-18: parked waiting_approval on paused run is NOT live work, but surfaces via hasParkedApprovals & blockingReasons.
  assert.equal(byId.get(approvalWorkerRun.id)?.isActive, false)
  assert.equal(byId.get(approvalWorkerRun.id)?.activity.hasParkedApprovals, true)
  assert.ok(byId.get(approvalWorkerRun.id)?.activity.blockingReasons.some(b => b.code === 'parked_approvals'))
  assert.equal(byId.get(labContainerRun.id)?.isActive, true)
}))

test('B1/B2/B3 + #607: ProjectNewRunSheet 3-card Scan Mode picker, removes Workers/Max turns/Scan depth/Approval Policy picker, preserves custom req caps, reuses PersonaFormModal, and wires onTestPersona', async () => {
  const src = readSrc('src/components/project/ProjectNewRunSheet.tsx')

  // B1: no workerConcurrency or workerMaxTurns controls or payload overrides
  assert.doesNotMatch(src, /name="workerConcurrency"/)
  assert.doesNotMatch(src, /name="workerMaxTurns"/)
  assert.doesNotMatch(src, /workerConcurrency\s*:/)
  assert.doesNotMatch(src, /workerMaxTurns\s*:/)
  assert.doesNotMatch(src, />Max turns</)

  // B2 + #607: 3-card Scan Mode picker (Passive / Supervised default / Autonomous), no Scan depth dropdown, no separate 3-card Approval Policy picker
  assert.doesNotMatch(src, /name="capabilityTier"/)
  assert.doesNotMatch(src, /Scan depth/)
  assert.doesNotMatch(src, /aria-label="Approval policy"/)
  assert.match(src, /label:\s*'Passive Scan'/)
  assert.match(src, /badge:\s*'Safest'/)
  assert.match(src, /label:\s*'Supervised Scan'/)
  assert.match(src, /badge:\s*'Recommended'/)
  assert.match(src, /useState<ScanMode>\('supervised'\)/)
  assert.doesNotMatch(src, /Ask before every write \(strict\)/)
  assert.match(src, /label:\s*'Autonomous Scan'/)
  assert.match(src, /badge:\s*'Risky'/)
  assert.match(src, /Runs write probes automatically without pausing for approval\. Best for staging or local labs\./)
  assert.match(src, /Not recommended for production environments/)
  const applyScanModeBlock = src.match(/function applyScanMode\([\s\S]*?\n  \}/)?.[0] ?? ''
  assert.ok(applyScanModeBlock.length > 0, 'Expected applyScanMode handler')
  assert.doesNotMatch(applyScanModeBlock, /setUnlimitedReqs\(/, 'Switching mode cards must not reset custom request cap')

  // Test Accounts section is visible across all 3 modes (not gated behind tier >= 2)
  assert.doesNotMatch(src, /\{tier >= 2 &&/)
  assert.match(src, /approvedPersonaIds:\s*selectedPersonaIds/)

  // Verify exact mode -> (capabilityTier, approvalPolicy) mapping via resolveRunSubmissionMode
  const resolveRunSubmissionMode = evalExportedFunction<
    (scanMode: 'passive' | 'supervised' | 'autonomous', count: number) => {
      capabilityTier: number
      approvalPolicy: string
    }
  >('src/components/project/ProjectNewRunSheet.tsx', 'resolveRunSubmissionMode')
  assert.deepEqual(resolveRunSubmissionMode('passive', 0), { capabilityTier: 1, approvalPolicy: 'auto_review' })
  assert.deepEqual(resolveRunSubmissionMode('passive', 2), { capabilityTier: 2, approvalPolicy: 'auto_review' })
  assert.deepEqual(resolveRunSubmissionMode('supervised', 0), { capabilityTier: 3, approvalPolicy: 'auto_review' })
  assert.deepEqual(resolveRunSubmissionMode('supervised', 2), { capabilityTier: 3, approvalPolicy: 'auto_review' })
  assert.deepEqual(resolveRunSubmissionMode('autonomous', 0), { capabilityTier: 3, approvalPolicy: 'yolo' })
  assert.deepEqual(resolveRunSubmissionMode('autonomous', 2), { capabilityTier: 3, approvalPolicy: 'yolo' })

  // B3: reuses PersonaFormModal (no inline registerPersona/parseCurlOrHeader) and wires onTestPersona on chips
  assert.match(src, /import\s*\{\s*PersonaFormModal\s*\}\s*from\s*'\.\/PersonaFormModal\.tsx'/)
  assert.match(src, /<PersonaFormModal\b/)
  assert.doesNotMatch(src, /\bregisterPersona\b/)
  assert.doesNotMatch(src, /\bparseCurlOrHeader\b/)
  assert.match(src, /onClick=\{\(\) => onTestPersona\(persona\)\}/)
  assert.match(src, /Verify sign-in/)
})

test('A9c/B6/#608: PersonaFormModal & ProjectPersonasTab keep clerk_client, remove Handle input & auto-generate unique handles, auto-populate Account label, place Header name outside Disclosure, and remove canaryMarkers UI', () => {
  const modalSrc = readSrc('src/components/project/PersonaFormModal.tsx')
  const tabSrc = readSrc('src/components/project/ProjectPersonasTab.tsx')

  // Preserves Clerk __client cookie option
  assert.match(modalSrc, /value="clerk_client"/)
  assert.match(modalSrc, /Clerk __client cookie \(auto-refresh\)/)

  // #608: Handle input removed from UI; Account label auto-populated; unique handle auto-generated
  assert.doesNotMatch(modalSrc, /name="handle"/)
  assert.doesNotMatch(modalSrc, /Handle \(lowercase identifier\)/)
  assert.match(modalSrc, /suggestNextAccountLabel\(existingPersonas\)/)
  assert.match(modalSrc, /deriveUniqueHandle\(/)

  const deriveUniqueHandle = evalExportedFunction<
    (label: string, existingHandles: readonly string[]) => string
  >('src/components/project/PersonaFormModal.tsx', 'deriveUniqueHandle')
  const suggestNextAccountLabel = evalExportedFunction<
    (existing: readonly { handle: string; roleLabel: string }[]) => string
  >('src/components/project/PersonaFormModal.tsx', 'suggestNextAccountLabel')

  assert.equal(deriveUniqueHandle('User A', []), 'user-a')
  assert.equal(deriveUniqueHandle('User A', ['user-a']), 'user-a-2')
  assert.equal(deriveUniqueHandle('User A', ['user-a', 'user-a-2']), 'user-a-3')
  assert.equal(deriveUniqueHandle('!!!', []), 'account')
  assert.match(deriveUniqueHandle('---Admin (Staging)---', []), /^[a-z0-9][a-z0-9_-]{0,47}$/)

  assert.equal(suggestNextAccountLabel([]), 'User A')
  assert.equal(suggestNextAccountLabel([{ handle: 'user-a', roleLabel: 'User A' }]), 'User B')
  assert.equal(
    suggestNextAccountLabel([
      { handle: 'user_a', roleLabel: 'Owner' },
      { handle: 'custom', roleLabel: 'User B (Staging)' },
    ]),
    'User C',
  )

  // A9c: Header name input appears BEFORE <Disclosure so HTML5 validation never silently fails while collapsed
  const headerNameIdx = modalSrc.indexOf('name="headerName"')
  const disclosureIdx = modalSrc.indexOf('<Disclosure')
  assert.ok(headerNameIdx > 0, 'Expected headerName input in PersonaFormModal')
  assert.ok(disclosureIdx > 0, 'Expected Disclosure in PersonaFormModal')
  assert.ok(headerNameIdx < disclosureIdx, 'Header name input must be outside collapsed Disclosure')

  // B6: dead Leak detection markers input and UI badge deleted
  assert.doesNotMatch(modalSrc, /Leak detection markers/i)
  assert.doesNotMatch(modalSrc, /name="canaryMarkers"/)
  assert.doesNotMatch(tabSrc, /leak detection/i)
  assert.doesNotMatch(tabSrc, /canaryMarkers/)

  // ProjectPersonasTab delegates creation to PersonaFormModal
  assert.match(tabSrc, /import\s*\{\s*PersonaFormModal\s*\}\s*from\s*'\.\/PersonaFormModal\.tsx'/)
  assert.match(tabSrc, /<PersonaFormModal\b/)
  assert.doesNotMatch(tabSrc, /\bregisterPersona\b/)
})

test('A8/B6: Inventory unifies reversible toggle + delete & hides Prepared JSON; Overview drops Approve write rules; Guardrails drops GET', () => {
  const invSrc = readSrc('src/components/project/ProjectInventoryTab.tsx')
  const ovSrc = readSrc('src/components/project/ProjectOverviewTab.tsx')
  const grdSrc = readSrc('src/components/project/ProjectGuardrailsTab.tsx')

  // Inventory: no raw Prepared response metadata (JSON), unified approve checkbox, delete host action
  assert.doesNotMatch(invSrc, /Prepared response metadata/i)
  assert.doesNotMatch(invSrc, /name="prepared"/)
  assert.match(invSrc, /approveInDefaultScope:\s*next/)
  assert.match(invSrc, /Delete host/)
  assert.match(invSrc, /onDeleteAsset/)

  // Overview: Approve write rules removed from Finish setup; run delete uses isActive
  assert.doesNotMatch(ovSrc, /Approve write rules/)
  assert.doesNotMatch(ovSrc, /AllowlistSetupSvg/)
  assert.match(ovSrc, /runToDelete\.isActive/)

  // Guardrails: GET removed from write-rules method selector while POST/PUT/PATCH remain
  assert.match(grdSrc, /<option value="POST">POST<\/option>/)
  assert.match(grdSrc, /<option value="PUT">PUT<\/option>/)
  assert.match(grdSrc, /<option value="PATCH">PATCH<\/option>/)
  assert.doesNotMatch(grdSrc, /<option value="GET">/)
})

test('B4/C: Settings sidebar rename, GitHub UI consolidation to /settings, liveGithubStatus fix, project.id keying, persona pruning, and sync error banner', () => {
  const shellSrc = readSrc('src/components/shell/AppShell.tsx')
  const sourcesSrc = readSrc('src/components/project/ProjectSourcesTab.tsx')
  const createGhSrc = readSrc('src/components/project/CreateProjectGithubBlock.tsx')
  const projRouteSrc = readSrc('src/routes/projects.$projectId.tsx')
  const indexRouteSrc = readSrc('src/routes/index.tsx')

  // B4: Sidebar nav link renamed to Settings
  assert.doesNotMatch(shellSrc, />Model settings</)
  assert.match(shellSrc, /<span className="min-w-0 flex-1 truncate">Settings<\/span>/)

  // B4: ProjectSourcesTab & CreateProjectGithubBlock delegate PAT/Device-Flow management to /settings
  assert.doesNotMatch(sourcesSrc, /useGithubDeviceFlow/)
  assert.doesNotMatch(sourcesSrc, /\bsaveGithubToken\b/)
  assert.doesNotMatch(sourcesSrc, /\bclearGithubToken\b/)
  assert.match(sourcesSrc, /to="\/settings"/)
  assert.doesNotMatch(sourcesSrc, /\bgithubPatStatus\./, 'ProjectSourcesTab must read liveGithubStatus instead of stale githubPatStatus')

  assert.doesNotMatch(createGhSrc, /useGithubDeviceFlow/)
  assert.doesNotMatch(createGhSrc, /\bsaveGithubToken\b/)
  assert.match(createGhSrc, /to="\/settings"/)

  // C: project.id keying, deleted persona ID filtering, activeRunsCount uses derived RunActivity, syncError banner
  assert.match(projRouteSrc, /<ProjectPageContent\s+key=\{data\.project\.id\}/)
  assert.match(projRouteSrc, /validPersonaIds\.has\(pid\)/)
  assert.match(projRouteSrc, /isRunDeleteBlocked\(r\.activity\)/)
  assert.match(projRouteSrc, /syncErrorBanner/)
  assert.match(projRouteSrc, /Initial GitHub repository sync failed/)

  // C: index.tsx captures initial sync failure instead of silent empty catch
  assert.doesNotMatch(indexRouteSrc, /catch\s*\{\s*\/\/ Non-blocking/)
  assert.match(indexRouteSrc, /syncError/)
})
