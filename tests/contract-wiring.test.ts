/**
 * Pillar 3 — Automated Dead-Knob & Wiring-Completeness Contract Test (< 2s).
 *
 * Guards against zombie half-wired controls, naming regressions, and deleted
 * UX clutter creeping back in:
 *   1. RunCommand completeness (`src/domain.ts` <-> `src/server/store-runs.ts` + `src/actions.ts`)
 *   2. Grant / Guardrail & broker reauth wiring (`src/server/execution.ts`)
 *   3. Zero `GUARDIAN_*` env lookups or `guardian.sqlite` references in `src/`, `worker/`, `scripts/serve.ts`
 *   4. UI simplification non-regression (`ProjectNewRunSheet`, `PersonaFormModal`, `ProjectGuardrailsTab`, `AppShell`)
 *   5. Persona login adapter parity (`personaLoginAdapters` <-> `src/server/persona-auth.ts`)
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readdirSync, readFileSync, rmSync, statSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, relative, resolve } from 'node:path'
import { test } from 'node:test'
import ts from 'typescript'
import { personaLoginAdapters, runCommand } from '../src/domain.ts'
import type { Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import { Store } from '../src/server/store.ts'
import type { Assignment, Run } from '../src/server/store.ts'

const repoRoot = resolve(new URL('..', import.meta.url).pathname)

function readRepoFile(relPath: string): string {
  return readFileSync(join(repoRoot, relPath), 'utf8')
}

function parseTs(relPath: string): { source: string; sf: ts.SourceFile } {
  const source = readRepoFile(relPath)
  return {
    source,
    sf: ts.createSourceFile(relPath, source, ts.ScriptTarget.Latest, true, ts.ScriptKind.TS),
  }
}

function findFirstAstNode<T extends ts.Node>(
  root: ts.Node,
  predicate: (node: ts.Node) => node is T,
): T | undefined {
  let found: T | undefined
  const visit = (node: ts.Node) => {
    if (found) return
    if (predicate(node)) {
      found = node
      return
    }
    ts.forEachChild(node, visit)
  }
  visit(root)
  return found
}

function extractSwitchCaseLiterals(switchStmt: ts.SwitchStatement, sf: ts.SourceFile): string[] {
  const cases: string[] = []
  for (const clause of switchStmt.caseBlock.clauses) {
    if (ts.isCaseClause(clause) && ts.isStringLiteralLike(clause.expression)) {
      cases.push(clause.expression.text)
    } else if (ts.isCaseClause(clause)) {
      throw new Error(`Expected string literal in switch case: ${clause.getText(sf)}`)
    }
  }
  return cases
}

function collectFiles(relRoots: readonly string[]): string[] {
  const out: string[] = []
  const visit = (absPath: string) => {
    const st = statSync(absPath)
    if (st.isDirectory()) {
      for (const entry of readdirSync(absPath)) {
        if (entry === 'node_modules' || entry === '.git') continue
        visit(join(absPath, entry))
      }
      return
    }
    out.push(absPath)
  }
  for (const rel of relRoots) visit(join(repoRoot, rel))
  return out
}

// ============================================================================
// 1. RunCommand completeness
// ============================================================================

test('Contract 1: every runCommand variant in src/domain.ts has a live handler in store-runs.ts and commandRun in actions.ts', () => {
  const schemaActions = runCommand.options.map((opt, idx) => {
    const actionLit = (opt as { shape?: { action?: { value?: unknown } } }).shape?.action?.value
    assert.equal(typeof actionLit, 'string', `runCommand.options[${idx}] must expose a literal action string`)
    return actionLit as string
  })
  assert.ok(schemaActions.length >= 15, `Expected full runCommand union, got ${schemaActions.length} variants`)
  assert.equal(new Set(schemaActions).size, schemaActions.length, 'runCommand must not contain duplicate action variants')

  const { sf: storeRunsSf } = parseTs('src/server/store-runs.ts')
  const commandMethod = findFirstAstNode(
    storeRunsSf,
    (node): node is ts.MethodDeclaration =>
      ts.isMethodDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'command',
  )
  assert.ok(commandMethod?.body, 'StoreRuns.command(input: RunCommand) not found in src/server/store-runs.ts')

  const actionSwitch = findFirstAstNode(
    commandMethod.body,
    (node): node is ts.SwitchStatement =>
      ts.isSwitchStatement(node) && node.expression.getText(storeRunsSf) === 'input.action',
  )
  assert.ok(actionSwitch, 'switch (input.action) not found inside StoreRuns.command()')
  const handledActions = extractSwitchCaseLiterals(actionSwitch, storeRunsSf)

  const missingInStore = schemaActions.filter(a => !handledActions.includes(a))
  assert.deepEqual(
    missingInStore,
    [],
    `runCommand variants missing handler in src/server/store-runs.ts: ${missingInStore.join(', ')}`,
  )

  const staleInStore = handledActions.filter(a => !schemaActions.includes(a))
  assert.deepEqual(
    staleInStore,
    [],
    `Stale switch cases in src/server/store-runs.ts not present in runCommand: ${staleInStore.join(', ')}`,
  )

  const actionsSrc = readRepoFile('src/actions.ts')
  const commandRunBlock = /export const commandRun = createServerFn[\s\S]*?\n\s*\}\)\n/.exec(actionsSrc)?.[0] ?? ''
  assert.ok(commandRunBlock.length > 0, 'commandRun server function not found in src/actions.ts')
  assert.match(commandRunBlock, /\.validator\(runCommand\)/, 'commandRun must validate input with runCommand')
  assert.match(commandRunBlock, /\.command\(data\b/, 'commandRun must forward validated data to store().command(...)')

  for (const match of commandRunBlock.matchAll(/data\.action\s*[!=]==\s*['"]([a-z0-9_]+)['"]/g)) {
    assert.ok(
      schemaActions.includes(match[1]),
      `commandRun references unknown runCommand action "${match[1]}"`,
    )
  }
})

// ============================================================================
// 2. Grant / Guardrail & broker reauth wiring completeness
// ============================================================================

test('Contract 2: Execution.buildGrant() and Execution/createBroker wire guardrails and setReauth', async t => {
  const { sf: execSf } = parseTs('src/server/execution.ts')

  const executionClass = findFirstAstNode(
    execSf,
    (node): node is ts.ClassDeclaration =>
      ts.isClassDeclaration(node) && node.name?.text === 'Execution',
  )
  assert.ok(executionClass, 'Execution class not found in src/server/execution.ts')

  const buildGrantMethod = findFirstAstNode(
    executionClass,
    (node): node is ts.MethodDeclaration =>
      ts.isMethodDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'buildGrant',
  )
  assert.ok(buildGrantMethod?.body, 'Execution.buildGrant() not found in src/server/execution.ts')
  const buildGrantBody = buildGrantMethod.body.getText(execSf)

  for (const wiredProp of ['sandboxWriteAllowlist', 'approvalPolicy', 'getMaxRpsPerOrigin', 'scopePolicy']) {
    assert.ok(
      buildGrantBody.includes(wiredProp),
      `Execution.buildGrant() must explicitly wire ${wiredProp}`,
    )
  }

  const createBrokerFn = findFirstAstNode(
    execSf,
    (node): node is ts.FunctionDeclaration =>
      ts.isFunctionDeclaration(node) && node.name?.text === 'createBroker',
  )
  assert.ok(createBrokerFn?.body, 'createBroker() not found in src/server/execution.ts')

  const ctorDecl = findFirstAstNode(
    executionClass,
    (node): node is ts.ConstructorDeclaration => ts.isConstructorDeclaration(node),
  )
  assert.ok(ctorDecl?.body, 'Execution constructor not found in src/server/execution.ts')
  const ctorBody = ctorDecl.body.getText(execSf)
  assert.ok(ctorBody.includes('createBroker('), 'Execution constructor must call createBroker()')
  assert.match(
    ctorBody,
    /this\.broker\.setReauth\([\s\S]*?this\.personaAuth\.requestReauth/,
    'Execution constructor must wire this.broker.setReauth() to this.personaAuth.requestReauth()',
  )

  // Behavioral check: instantiate Execution without custom broker and verify buildGrant + setReauth live wiring.
  const dir = mkdtempSync(join(tmpdir(), 'kovo-contract-wiring-'))
  const storage = new Store(dir)
  t.after(() => {
    storage.close()
    rmSync(dir, { recursive: true, force: true })
  })

  const origin = 'https://contract-target.example.invalid'
  const allowlist = [{ origin, method: 'POST', pathPattern: '/api/safe/*' }]
  const project = storage.createProject({
    requestId: randomUUID(),
    name: 'Contract Target',
    seeds: [origin],
    environment: 'public',
    sandboxWriteAllowlist: allowlist,
  })

  const { id: runId } = storage.createRun({
    requestId: randomUUID(),
    projectId: project.id,
    goal: 'Verify grant wiring',
    sourceMode: 'public',
    capabilityTier: 2,
    approvalPolicy: 'strict',
    maxRpsPerOrigin: 7,
  } as Parameters<Store['createRun']>[0])
  storage.command(runCommand.parse({ requestId: randomUUID(), runId, action: 'discover', consent: true }))
  const discovered = storage.run(runId)
  storage.command(runCommand.parse({
    requestId: randomUUID(),
    runId,
    action: 'scope',
    assetIds: discovered.candidates.map(c => c.id),
    expectedScopeRevision: discovered.scopeRevision,
    consent: true,
  }))
  storage.updateRun(runId, { phase: 'investigation', status: 'running' })
  const liveRun = storage.run(runId)
  const worker = storage.makeWorker(liveRun, 'investigation', liveRun.candidates[0], 'Contract check', 'Verify grant wiring')

  const execution = new Execution(storage)
  t.after(() => execution.stop())

  const built = (execution as unknown as {
    buildGrant: (
      job: { assignment: Assignment; origins: Set<string>; controller: AbortController },
      run: Run,
      permitted: ReadonlySet<string>,
    ) => { grant: Grant }
  }).buildGrant(
    { assignment: worker, origins: new Set([origin]), controller: new AbortController() },
    liveRun,
    new Set([origin]),
  )

  assert.deepEqual(built.grant.sandboxWriteAllowlist, allowlist)
  assert.equal(built.grant.approvalPolicy, 'strict')
  assert.equal(built.grant.getMaxRpsPerOrigin?.(), 7)
  assert.ok(built.grant.scopePolicy, 'grant.scopePolicy must be populated')
  assert.deepEqual(built.grant.scopePolicy, storage.scopePolicy(liveRun))

  // Dynamic RPS getter reflects live store updates.
  storage.updateRun(runId, { maxRpsPerOrigin: 3 })
  assert.equal(built.grant.getMaxRpsPerOrigin?.(), 3)

  // Verify broker received a live reauth handler wired to execution.personaAuth.requestReauth.
  const reauthHandler = (execution.broker as unknown as {
    reauthHandler?: (personaHandle: string) => Promise<boolean>
  }).reauthHandler
  assert.equal(typeof reauthHandler, 'function', 'execution.broker must have reauthHandler wired via setReauth')

  const calls: string[] = []
  const origRequestReauth = execution.personaAuth.requestReauth.bind(execution.personaAuth)
  execution.personaAuth.requestReauth = async (handle: string) => {
    calls.push(handle)
    return false
  }
  t.after(() => {
    execution.personaAuth.requestReauth = origRequestReauth
  })
  const reauthed = await reauthHandler!('user_a')
  assert.equal(reauthed, false)
  assert.deepEqual(calls, ['user_a'], 'broker reauthHandler must delegate to personaAuth.requestReauth')
})

// ============================================================================
// 3. Zero GUARDIAN_* env fallbacks / guardian.sqlite regressions
// ============================================================================

test('Contract 3: zero GUARDIAN_* env lookups and zero guardian.sqlite references in src/, worker/, scripts/serve.ts', () => {
  const files = collectFiles(['src', 'worker', 'scripts/serve.ts'])
  assert.ok(files.length > 50, `Expected source tree files to scan, found ${files.length}`)

  const envHits: string[] = []
  const sqliteHits: string[] = []

  for (const absPath of files) {
    const content = readFileSync(absPath, 'utf8')
    const rel = relative(repoRoot, absPath)
    if (/\bGUARDIAN_[A-Z0-9_]+\b/.test(content)) {
      envHits.push(rel)
    }
    if (/guardian\.sqlite/i.test(content)) {
      sqliteHits.push(rel)
    }
  }

  assert.deepEqual(envHits, [], `Found forbidden GUARDIAN_* env var references in: ${envHits.join(', ')}`)
  assert.deepEqual(sqliteHits, [], `Found forbidden guardian.sqlite references in: ${sqliteHits.join(', ')}`)
})

// ============================================================================
// 4. UI simplification non-regression
// ============================================================================

test('Contract 4: removed duplicative UI controls have not crept back into components', () => {
  const newRunSheet = readRepoFile('src/components/project/ProjectNewRunSheet.tsx')
  assert.ok(!newRunSheet.includes('workerConcurrency'), 'ProjectNewRunSheet.tsx must not reintroduce workerConcurrency')
  assert.ok(!newRunSheet.includes('workerMaxTurns'), 'ProjectNewRunSheet.tsx must not reintroduce workerMaxTurns')
  assert.ok(!/scan\s+depth/i.test(newRunSheet), 'ProjectNewRunSheet.tsx must not reintroduce "Scan depth"')

  const personaModal = readRepoFile('src/components/project/PersonaFormModal.tsx')
  assert.ok(!/name=["']handle["']/.test(personaModal), 'PersonaFormModal.tsx must not reintroduce a user-facing handle input')
  assert.ok(!/\bsetHandle\b/.test(personaModal), 'PersonaFormModal.tsx must not reintroduce setHandle state for user-facing Handle input')
  assert.ok(!/>\s*Handle\s*</i.test(personaModal), 'PersonaFormModal.tsx must not reintroduce a user-facing Handle label')
  assert.ok(!/name=["']canaryMarkers["']/.test(personaModal), 'PersonaFormModal.tsx must not reintroduce a canaryMarkers input')
  assert.ok(!/\bsetCanaryMarkers\b/.test(personaModal), 'PersonaFormModal.tsx must not reintroduce setCanaryMarkers state')
  assert.ok(!/canary\s+markers?/i.test(personaModal), 'PersonaFormModal.tsx must not reintroduce canaryMarkers UI copy')

  const guardrailsTab = readRepoFile('src/components/project/ProjectGuardrailsTab.tsx')
  assert.ok(guardrailsTab.includes('<option value="POST">POST</option>'), 'ProjectGuardrailsTab.tsx should still offer POST write rules')
  assert.ok(
    !/<option[^>]*value=["']GET["']/i.test(guardrailsTab),
    'ProjectGuardrailsTab.tsx must not reintroduce GET as a write rule option',
  )

  const appShell = readRepoFile('src/components/shell/AppShell.tsx')
  assert.ok(!/model\s+settings/i.test(appShell), 'AppShell.tsx must not reintroduce "Model settings"')
})

// ============================================================================
// 5. Persona login adapter parity
// ============================================================================

test('Contract 5: every personaLoginAdapters entry has a live dispatch branch in src/server/persona-auth.ts', () => {
  const { source: personaAuthSrc, sf: personaAuthSf } = parseTs('src/server/persona-auth.ts')

  const authMethod = findFirstAstNode(
    personaAuthSf,
    (node): node is ts.MethodDeclaration =>
      ts.isMethodDeclaration(node) && ts.isIdentifier(node.name) && node.name.text === 'authenticatePersona',
  )
  assert.ok(authMethod?.body, 'authenticatePersona() not found in src/server/persona-auth.ts')
  const authBody = authMethod.body.getText(personaAuthSf)

  assert.ok(
    authBody.includes("config.adapter === 'auto'"),
    "persona-auth.ts authenticatePersona() must handle 'auto' adapter resolution",
  )

  const adapterSwitch = findFirstAstNode(
    authMethod.body,
    (node): node is ts.SwitchStatement =>
      ts.isSwitchStatement(node) && node.expression.getText(personaAuthSf) === 'adapter',
  )
  assert.ok(adapterSwitch, 'switch (adapter) not found inside authenticatePersona()')
  const dispatchedCases = extractSwitchCaseLiterals(adapterSwitch, personaAuthSf)

  const explicitAdapters = personaLoginAdapters.filter(a => a !== 'auto')
  const missingCases = explicitAdapters.filter(a => !dispatchedCases.includes(a))
  assert.deepEqual(
    missingCases,
    [],
    `personaLoginAdapters missing switch branch in src/server/persona-auth.ts: ${missingCases.join(', ')}`,
  )

  const switchText = adapterSwitch.getText(personaAuthSf)
  for (const adapter of explicitAdapters) {
    const caseRe = new RegExp(`case\\s+['"]${adapter}['"]:\\s*[\\r\\n]+\\s*return\\s+await\\s+this\\.(authenticate\\w+)\\(`)
    const match = caseRe.exec(switchText)
    assert.ok(match, `switch (adapter) case '${adapter}' must dispatch to a this.authenticate*() method`)
    const methodName = match[1]
    assert.ok(
      personaAuthSrc.includes(`async ${methodName}(`),
      `Dispatched method ${methodName}() for adapter '${adapter}' must exist on PersonaAuthManager`,
    )
  }
})
