import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import test from 'node:test'
import ts from 'typescript'
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
  // Provide LAB_ENV_KEY_RE if referenced by parseLabEnv
  const keyRe = 'const LAB_ENV_KEY_RE = /^[A-Z_][A-Z0-9_]{0,63}$/;'
  return new Function(`${keyRe}\n${js}\nreturn ${fnName};`)() as T
}

function withTempStore(fn: (ctx: { dir: string; store: Store }) => Promise<void> | void) {
  return async () => {
    const dir = mkdtempSync(join(tmpdir(), 'kovo-ux-edit-proj-guard-'))
    const store = new Store(dir, { ftsMode: 'preview' })
    try {
      await fn({ dir, store })
    } finally {
      store.close()
      rmSync(dir, { recursive: true, force: true })
    }
  }
}

test('updateProject updates name, environment, seeds, defaultScope, projectAssets, and clears labConfig when switching to public', async t => {
  const prevLab = process.env.KOVO_ALLOW_LOCAL_LAB
  process.env.KOVO_ALLOW_LOCAL_LAB = '1'
  t.after(() => {
    if (prevLab === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = prevLab
  })

  await withTempStore(({ store }) => {
    const created = store.createProject({
      requestId: randomUUID(),
      name: 'Original Project',
      seeds: ['https://app.northstar.example'],
      environment: 'public',
    })

    // Rejects HTTP origin on public project
    assert.throws(() => store.projectsRepo.updateProject({
      requestId: randomUUID(),
      projectId: created.id,
      seeds: ['http://localhost:3000'],
    }), /Enter a hostname or HTTPS origin/)

    // Switch to local-lab with localhost seed and enable labConfig
    const reqId = randomUUID()
    const switchedToLab = store.projectsRepo.updateProject({
      requestId: reqId,
      projectId: created.id,
      name: 'Renamed Lab Project',
      environment: 'local-lab',
      seeds: ['http://localhost:3000', 'http://localhost:3001'],
    })
    assert.equal(switchedToLab.name, 'Renamed Lab Project')
    assert.equal(switchedToLab.environment, 'local-lab')
    assert.deepEqual(switchedToLab.seeds, ['http://localhost:3000', 'http://localhost:3001'])
    assert.deepEqual(switchedToLab.defaultScope, ['http://localhost:3000', 'http://localhost:3001'])

    // Idempotent replay with same requestId
    assert.deepEqual(
      store.projectsRepo.updateProject({
        requestId: reqId,
        projectId: created.id,
        name: 'Renamed Lab Project',
        environment: 'local-lab',
        seeds: ['http://localhost:3000', 'http://localhost:3001'],
      }),
      switchedToLab,
    )

    const detailLab = store.projectDetail(created.id)
    assert.ok(detailLab.assets.some(a => a.origin === 'http://localhost:3000'))
    assert.ok(detailLab.assets.some(a => a.origin === 'http://localhost:3001'))

    store.updateProjectLabConfig({
      requestId: randomUUID(),
      projectId: created.id,
      labConfig: {
        enabled: true,
        healthPath: '/health',
        repo: 'acme/web',
        startCommand: 'npm start',
        memoryLimit: '512m',
        cpus: '1.0',
        pidsLimit: 128,
        env: { NODE_ENV: 'test' },
      },
    })
    assert.equal(store.project(created.id).labConfig?.enabled, true)

    // Switching back to public without updating localhost seeds fails validation
    assert.throws(() => store.projectsRepo.updateProject({
      requestId: randomUUID(),
      projectId: created.id,
      environment: 'public',
    }), /Enter a hostname or HTTPS origin/)

    // Switching back to public with valid HTTPS seeds succeeds and clears labConfig
    const backToPublic = store.projectsRepo.updateProject({
      requestId: randomUUID(),
      projectId: created.id,
      environment: 'public',
      seeds: ['https://prod.northstar.example'],
    })
    assert.equal(backToPublic.environment, 'public')
    assert.deepEqual(backToPublic.seeds, ['https://prod.northstar.example'])
    assert.equal(store.project(created.id).labConfig, null)
  })()
})

test('updateWorkspaceName updates DB and in-memory workspace summary', withTempStore(({ store }) => {
  const initial = store.listWorkspace()
  assert.equal(initial.workspace.name, 'Personal workspace')

  const renamed = store.projectsRepo.updateWorkspaceName({
    requestId: randomUUID(),
    workspaceId: initial.workspace.id,
    name: 'Acme Security Team',
  })
  assert.deepEqual(renamed, { id: initial.workspace.id, name: 'Acme Security Team' })
  assert.equal(store.listWorkspace().workspace.name, 'Acme Security Team')
  assert.equal(store.workspaceSummary().workspace.name, 'Acme Security Team')

  assert.throws(() => store.projectsRepo.updateWorkspaceName({
    requestId: randomUUID(),
    workspaceId: randomUUID(),
    name: 'Wrong Workspace',
  }), /Workspace not found/)

  assert.throws(() => store.projectsRepo.updateWorkspaceName({
    requestId: randomUUID(),
    name: '   ',
  }))
}))

test('updateProjectAsset and clearProjectAssetAccessPolicy enforce scope, collision, and policy cleanup', withTempStore(({ store }) => {
  const created = store.createProject({
    requestId: randomUUID(),
    name: 'Asset Edit Project',
    seeds: ['https://app.northstar.example'],
    environment: 'public',
    includeSubdomains: true,
  })
  const added = store.addProjectAsset({
    requestId: randomUUID(),
    projectId: created.id,
    origin: 'https://docs.northstar.example',
    source: 'Manual entry',
    thirdParty: false,
    includeSubdomains: true,
  })

  // Import an access policy onto the asset
  store.importProjectAccessPolicy({
    requestId: randomUUID(),
    projectId: created.id,
    snapshot: {
      origin: 'https://docs.northstar.example',
      recordedAt: new Date().toISOString(),
      expected: [{ caseId: 'case-1', decision: 'allow', role: 'member', capability: 'read' }],
      observed: [],
    },
  })
  assert.ok(store.projectDetail(created.id).assets.find(a => a.id === added.id)?.accessPolicy)

  // Updating asset origin + source + thirdParty updates project assets and disables includeSubdomains
  const updated = store.projectsRepo.updateProjectAsset({
    requestId: randomUUID(),
    projectId: created.id,
    assetId: added.id,
    origin: 'https://help.northstar.example',
    source: 'Partner portal',
    thirdParty: true,
  })
  assert.equal(updated.origin, 'https://help.northstar.example')
  assert.equal(updated.source, 'Partner portal')
  assert.equal(updated.thirdParty, true)
  assert.equal(updated.includeSubdomains, false)

  // Origin collision with existing seed throws
  assert.throws(() => store.projectsRepo.updateProjectAsset({
    requestId: randomUUID(),
    projectId: created.id,
    assetId: added.id,
    origin: 'https://app.northstar.example',
  }), /already exists/)

  // Clear access policy
  const cleared = store.projectsRepo.clearProjectAssetAccessPolicy({
    requestId: randomUUID(),
    projectId: created.id,
    assetId: added.id,
  })
  assert.equal(cleared.cleared, true)
  assert.equal(store.projectDetail(created.id).assets.find(a => a.id === added.id)?.accessPolicy ?? null, null)
}))

test('Guardrails parseLabEnv/formatLabEnv and UI CRUD stream 1 wiring', () => {
  const formatLabEnv = evalExportedFunction<(env: Record<string, string> | undefined) => string>(
    'src/components/project/ProjectGuardrailsTab.tsx',
    'formatLabEnv',
  )
  const parseLabEnv = evalExportedFunction<(raw: string) => Record<string, string> | undefined>(
    'src/components/project/ProjectGuardrailsTab.tsx',
    'parseLabEnv',
  )

  assert.equal(formatLabEnv(undefined), '')
  assert.equal(formatLabEnv({ NODE_ENV: 'test', PORT: '8080' }), 'NODE_ENV=test\nPORT=8080')
  assert.equal(parseLabEnv('   '), undefined)
  assert.deepEqual(parseLabEnv('# comment\nNODE_ENV=test\nAPI_URL=http://localhost:3000/v1=a'), {
    NODE_ENV: 'test',
    API_URL: 'http://localhost:3000/v1=a',
  })
  assert.deepEqual(parseLabEnv('{"NODE_ENV":"test"}'), { NODE_ENV: 'test' })
  assert.throws(() => parseLabEnv('bad_key=1'), /Invalid environment variable key/)

  const actionsSrc = readSrc('src/actions.ts')
  const projectRouteSrc = readSrc('src/routes/projects.$projectId.tsx')
  const editModalSrc = readSrc('src/components/project/ProjectEditModal.tsx')
  const settingsSrc = readSrc('src/routes/settings.tsx')
  const guardrailsSrc = readSrc('src/components/project/ProjectGuardrailsTab.tsx')
  const inventorySrc = readSrc('src/components/project/ProjectInventoryTab.tsx')

  // 1. Project edit + removeProjectAsset moved to actions.ts
  assert.match(actionsSrc, /export const updateProjectAction\s*=/)
  assert.match(actionsSrc, /export const removeProjectAsset\s*=/)
  assert.doesNotMatch(projectRouteSrc, /createServerFn/)
  assert.match(projectRouteSrc, /Edit project/)
  assert.match(projectRouteSrc, /<ProjectEditModal\b/)
  assert.match(editModalSrc, /updateProjectAction/)

  // 2. Workspace rename in actions.ts + settings.tsx
  assert.match(actionsSrc, /export const updateWorkspaceAction\s*=/)
  assert.match(settingsSrc, /updateWorkspaceAction/)
  assert.match(settingsSrc, /name="workspaceName"/)

  // 3. Guardrails inline edit + advanced lab settings + clear lab config
  assert.match(guardrailsSrc, /name="editAllowOrigin"/)
  assert.match(guardrailsSrc, /name="editAllowMethod"/)
  assert.match(guardrailsSrc, /name="editAllowPathPattern"/)
  assert.match(guardrailsSrc, /Advanced lab settings/)
  for (const field of ['repo', 'startCommand', 'dockerfile', 'image', 'env', 'memoryLimit', 'cpus', 'pidsLimit']) {
    assert.match(guardrailsSrc, new RegExp(`name="${field}"`))
  }
  assert.match(guardrailsSrc, /Reset \/ Clear lab config/)
  assert.match(guardrailsSrc, /labConfig:\s*null/)

  // 4. Host/Asset edit + clear access policy
  assert.match(actionsSrc, /export const updateProjectAssetAction\s*=/)
  assert.match(actionsSrc, /export const clearProjectAssetAccessPolicyAction\s*=/)
  assert.match(inventorySrc, /updateProjectAssetAction/)
  assert.match(inventorySrc, /clearProjectAssetAccessPolicyAction/)
  assert.match(inventorySrc, /Clear policy/)
  assert.match(inventorySrc, /Edit host/)
})
