/**
 * Composition-Root Capability Manifest Test (CQ-11).
 *
 * Builds the real `AppRuntime` + `Execution` composition root for `docker`, `dood`, and
 * `local-jq` backends and snapshots:
 *   - registered worker tools (from `buildWorkerTools`, AST-pinned to `ExecWorkerRunner` + `Execution`)
 *   - reachable floor recipe IDs (core + Cut 3 + persisted envelope + wired specKind mappings)
 *   - registered terminal oracle families (v8 families + single-hop rules)
 *   - live approval & scope binders wired onto `Grant`, `RequestBroker`, and `Execution`
 *
 * Diffs against `tests/fixtures/capability-manifest.json`. Any capability removal must be
 * intentional and accompanied by a `Contract-change:` commit trailer.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, readFileSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import ts from 'typescript'
import { LocalJqBackend } from '../scripts/benchmark-backend.ts'
import { runUnwiredCheck } from '../scripts/check-unwired.ts'
import { runCommand } from '../src/domain.ts'
import { floorRecipeIds } from '../src/replay-spec.ts'
import { buildWorkerTools, type WorkerToolHandlers } from '../src/server/agent-session.ts'
import { createAppRuntime } from '../src/server/app-runtime.ts'
import type { Grant } from '../src/server/broker.ts'
import { Execution } from '../src/server/execution.ts'
import {
  CUT3_FLOOR_RECIPE_IDS,
  FLOOR_RECIPE_IDS,
  WIRED_SPECKIND_RECIPES,
} from '../src/server/floor-recipes.ts'
import type { Assignment, Run, Store } from '../src/server/store.ts'
import {
  defaultTerminalOracleRegistry,
  REGISTERED_V8_ORACLE_FAMILIES,
  SINGLE_HOP_ORACLE_RULES,
} from '../src/server/terminal-oracle-registry.ts'
import {
  LinuxWorkerBackend,
  resolveDoodMountArg,
  resolveDoodScratchConfig,
  type WorkerBackend,
} from '../src/server/worker-backend.ts'

const repoRoot = resolve(new URL('..', import.meta.url).pathname)
const fixturePath = join(repoRoot, 'tests/fixtures/capability-manifest.json')

export type BackendProfile = 'docker' | 'dood' | 'local-jq'

export interface BackendCapabilitySnapshot {
  backendKind: BackendProfile
  doodMode: 'none' | 'host_bind' | 'volume_subpath'
  supportsVerifyScript: boolean
  registeredTools: string[]
  reachableRecipes: {
    core: string[]
    cut3: string[]
    persisted: string[]
    wiredSpecKinds: string[]
  }
  oracleFamilies: {
    singleHopRules: string[]
    v8Families: string[]
  }
  approvalBinders: {
    grantBinders: string[]
    brokerReauthWired: boolean
    tier3CoordinatorWired: boolean
    stateChangeLedgerWired: boolean
    burstApprovalInstancesWired: boolean
  }
}

export interface CapabilityManifest {
  version: 1
  backends: Record<BackendProfile, BackendCapabilitySnapshot>
}

export interface CapabilityManifestDiff {
  added: string[]
  removed: string[]
  changed: string[]
}

function parseSourceFile(relPath: string): ts.SourceFile {
  const full = join(repoRoot, relPath)
  return ts.createSourceFile(relPath, readFileSync(full, 'utf8'), ts.ScriptTarget.Latest, true, ts.ScriptKind.TS)
}

function extractObjectLiteralKeys(obj: ts.ObjectLiteralExpression): string[] {
  const keys: string[] = []
  for (const prop of obj.properties) {
    if (ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop) || ts.isMethodDeclaration(prop)) {
      if (ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name)) {
        keys.push(prop.name.text)
      }
    } else if (ts.isSpreadAssignment(prop)) {
      let expr: ts.Expression = prop.expression
      while (ts.isParenthesizedExpression(expr)) expr = expr.expression
      if (ts.isConditionalExpression(expr)) {
        for (const branch of [expr.whenTrue, expr.whenFalse]) {
          let inner: ts.Expression = branch
          while (ts.isParenthesizedExpression(inner)) inner = inner.expression
          if (ts.isObjectLiteralExpression(inner)) {
            keys.push(...extractObjectLiteralKeys(inner))
          }
        }
      }
    }
  }
  return keys
}

function findFirstNode<T extends ts.Node>(root: ts.Node, pred: (n: ts.Node) => n is T): T | undefined {
  let found: T | undefined
  const visit = (n: ts.Node) => {
    if (found) return
    if (pred(n)) { found = n; return }
    ts.forEachChild(n, visit)
  }
  visit(root)
  return found
}

/**
 * Extract the exact WorkerToolHandlers key set constructed in `ExecWorkerRunner` +
 * `Execution.buildBrokeredTransportHandlers()` via TypeScript AST, so any added or removed
 * tool handler immediately shows up in the capability manifest diff.
 */
function discoverProductionHandlerKeys(): { unconditional: string[]; verifyScriptGated: string[] } {
  const runnerSf = parseSourceFile('src/server/exec-worker-runner.ts')
  const execSf = parseSourceFile('src/server/execution.ts')
  const transportSf = parseSourceFile('src/server/exec-brokered-transport.ts')

  const keys = new Set<string>()
  const verifyScriptGated = new Set<string>()

  // 1. ExecWorkerRunner shared handlers (`satisfies Partial<WorkerToolHandlers>`)
  const visitRunner = (node: ts.Node) => {
    if (
      ts.isSatisfiesExpression(node)
      && node.type.getText(runnerSf).includes('WorkerToolHandlers')
      && ts.isObjectLiteralExpression(node.expression)
    ) {
      for (const k of extractObjectLiteralKeys(node.expression)) keys.add(k)
    }
    if (
      ts.isVariableDeclaration(node)
      && ts.isIdentifier(node.name)
      && node.name.text === 'handlers'
      && node.type?.getText(runnerSf) === 'WorkerToolHandlers'
      && node.initializer
      && ts.isObjectLiteralExpression(node.initializer)
    ) {
      for (const prop of node.initializer.properties) {
        if (ts.isSpreadAssignment(prop)) {
          let expr: ts.Expression = prop.expression
          while (ts.isParenthesizedExpression(expr)) expr = expr.expression
          if (ts.isConditionalExpression(expr) && expr.condition.getText(runnerSf).includes('backendSupportsVerifyScript')) {
            let whenTrue: ts.Expression = expr.whenTrue
            while (ts.isParenthesizedExpression(whenTrue)) whenTrue = whenTrue.expression
            if (ts.isObjectLiteralExpression(whenTrue)) {
              for (const k of extractObjectLiteralKeys(whenTrue)) verifyScriptGated.add(k)
            }
          }
        } else if (
          (ts.isPropertyAssignment(prop) || ts.isShorthandPropertyAssignment(prop) || ts.isMethodDeclaration(prop))
          && (ts.isIdentifier(prop.name) || ts.isStringLiteral(prop.name))
        ) {
          keys.add(prop.name.text)
        }
      }
    }
    ts.forEachChild(node, visitRunner)
  }
  visitRunner(runnerSf)

  // 2. Execution.buildBrokeredTransportHandlers() delegates to exec-brokered-transport.ts
  const transportMethod = findFirstNode(
    execSf,
    (n): n is ts.MethodDeclaration =>
      ts.isMethodDeclaration(n) && ts.isIdentifier(n.name) && n.name.text === 'buildBrokeredTransportHandlers',
  )
  assert.ok(transportMethod?.body, 'Execution.buildBrokeredTransportHandlers() not found')
  const execDirectReturn = transportMethod.body.statements.find(
    (s): s is ts.ReturnStatement => ts.isReturnStatement(s) && Boolean(s.expression && ts.isObjectLiteralExpression(s.expression)),
  )
  let returnExpr: ts.ObjectLiteralExpression | undefined
  if (execDirectReturn?.expression && ts.isObjectLiteralExpression(execDirectReturn.expression)) {
    returnExpr = execDirectReturn.expression
  } else {
    const execDelegateReturn = transportMethod.body.statements.find(
      (s): s is ts.ReturnStatement =>
        ts.isReturnStatement(s)
        && Boolean(
          s.expression
          && ts.isCallExpression(s.expression)
          && ts.isIdentifier(s.expression.expression)
          && s.expression.expression.text === 'buildBrokeredTransportHandlers',
        ),
    )
    assert.ok(execDelegateReturn, 'Execution.buildBrokeredTransportHandlers() must return handlers or delegate to buildBrokeredTransportHandlers()')
    const transportFn = findFirstNode(
      transportSf,
      (n): n is ts.FunctionDeclaration =>
        ts.isFunctionDeclaration(n) && Boolean(n.name && n.name.text === 'buildBrokeredTransportHandlers'),
    )
    assert.ok(transportFn?.body, 'exec-brokered-transport.ts buildBrokeredTransportHandlers() not found')
    const transportReturn = transportFn.body.statements.find(
      (s): s is ts.ReturnStatement => ts.isReturnStatement(s) && Boolean(s.expression && ts.isObjectLiteralExpression(s.expression)),
    )
    if (transportReturn?.expression && ts.isObjectLiteralExpression(transportReturn.expression)) {
      returnExpr = transportReturn.expression
    }
  }
  assert.ok(returnExpr, 'buildBrokeredTransportHandlers return literal not found')
  for (const k of extractObjectLiteralKeys(returnExpr)) keys.add(k)
  assert.ok(keys.has('request_http'), 'buildBrokeredTransportHandlers must expose request_http')

  for (const gated of verifyScriptGated) keys.delete(gated)
  return {
    unconditional: [...keys].sort(),
    verifyScriptGated: [...verifyScriptGated].sort(),
  }
}

function buildStubHandlers(keys: readonly string[]): WorkerToolHandlers {
  const noop = async () => ({})
  const handlers: Record<string, unknown> = {}
  for (const key of keys) {
    handlers[key] = noop
  }
  return handlers as unknown as WorkerToolHandlers
}

async function emitBackendSnapshot(
  profile: BackendProfile,
  handlerKeys: { unconditional: string[]; verifyScriptGated: string[] },
): Promise<BackendCapabilitySnapshot> {
  const dir = mkdtempSync(join(tmpdir(), `kovo-cap-manifest-${profile}-`))
  const runtime = createAppRuntime({
    dataDir: dir,
    maintenance: false,
    autoStartMaintenance: false,
  })
  let execution: Execution | null = null
  try {
    const doodEnv: NodeJS.ProcessEnv = profile === 'dood'
      ? {
          KOVO_HOST_SCRATCH_DIR: '/host/kovo-scratch',
          KOVO_CONTAINER_SCRATCH_DIR: '/scratch',
        }
      : {}
    const doodConfig = resolveDoodScratchConfig(doodEnv)
    if (profile === 'dood') {
      assert.equal(doodConfig?.mode, 'host_bind', 'DooD profile must resolve host_bind scratch config')
      assert.equal(
        resolveDoodMountArg('/scratch/session-1/rpc', '/kovo-rpc', { readonly: true, env: doodEnv }),
        'type=bind,source=/host/kovo-scratch/session-1/rpc,target=/kovo-rpc,readonly',
        'DooD mount resolver must translate container scratch subpath to host bind path',
      )
    } else {
      assert.equal(doodConfig, null, `${profile} profile must not enable DooD scratch config`)
    }

    const backend: WorkerBackend = profile === 'local-jq'
      ? new LocalJqBackend()
      : new LinuxWorkerBackend({
          workspace: { id: runtime.store.workspace.id, directory: dir },
        })

    execution = new Execution(runtime.store, { runtime, backend })
    assert.equal(runtime.hasStore(), true, `${profile}: AppRuntime must own Store`)
    assert.equal(runtime.hasCanaryBroker(), true, `${profile}: AppRuntime must attach CanaryBroker`)

    const internals = execution as unknown as {
      verifier: { backendSupportsVerifyScript(): boolean }
      tier3Approvals: unknown
      stateChangeApprovals: unknown
      burstApprovalInstances: unknown
      buildGrant: (
        job: { assignment: Assignment; origins: Set<string>; controller: AbortController },
        run: Run,
        permitted: ReadonlySet<string>,
      ) => { grant: Grant }
    }

    const supportsVerifyScript = internals.verifier.backendSupportsVerifyScript()

    // Wire WorkerToolHandlers identically to ExecWorkerRunner for this backend.
    const activeHandlerKeys = supportsVerifyScript
      ? [...handlerKeys.unconditional, ...handlerKeys.verifyScriptGated]
      : [...handlerKeys.unconditional]
    const registeredTools = buildWorkerTools(
      buildStubHandlers(activeHandlerKeys),
      value => value,
      new AbortController().signal,
      8192,
      () => {},
    ).map(tool => tool.name).sort()

    // Build a live Grant through Execution.buildGrant() to verify all approval/scope binders.
    const storage: Store = runtime.store
    const origin = `https://${profile}.capability-manifest.example.invalid`
    const project = storage.createProject({
      requestId: randomUUID(),
      name: `Manifest ${profile}`,
      seeds: [origin],
      environment: 'public',
      sandboxWriteAllowlist: [{ origin, method: 'POST', pathPattern: '/api/safe/*' }],
    })
    const { id: runId } = storage.createRun({
      requestId: randomUUID(),
      projectId: project.id,
      goal: 'Snapshot composition-root capability manifest',
      sourceMode: 'public',
      capabilityTier: 3,
      approvalPolicy: 'strict',
      maxRpsPerOrigin: 5,
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
    const worker = storage.makeWorker(liveRun, 'investigation', liveRun.candidates[0], 'Manifest', 'Snapshot grant binders')
    const { grant } = internals.buildGrant(
      { assignment: worker, origins: new Set([origin]), controller: new AbortController() },
      liveRun,
      new Set([origin]),
    )

    const grantRecord = grant as unknown as Record<string, unknown>
    const binderKeys = [
      'approvalLeases',
      'approvalPolicy',
      'audit',
      'canRead',
      'getMaxRpsPerOrigin',
      'isStateChangeApproved',
      'mintCanary',
      'sandboxWriteAllowlist',
      'scopePolicy',
    ].filter(key => grantRecord[key] !== undefined && grantRecord[key] !== null).sort()

    const reauthHandler = (execution.broker as unknown as { reauthHandler?: unknown }).reauthHandler

    return {
      backendKind: profile,
      doodMode: doodConfig?.mode ?? 'none',
      supportsVerifyScript,
      registeredTools,
      reachableRecipes: {
        core: [...FLOOR_RECIPE_IDS].sort(),
        cut3: [...CUT3_FLOOR_RECIPE_IDS].sort(),
        persisted: [...floorRecipeIds].sort(),
        wiredSpecKinds: WIRED_SPECKIND_RECIPES
          .map(r => `${r.specKind}:${r.recipe ?? 'null'}:[${[...r.vulnClasses].sort().join(',')}]`)
          .sort(),
      },
      oracleFamilies: {
        singleHopRules: [...defaultTerminalOracleRegistry.listRegisteredRules()].sort(),
        v8Families: [...defaultTerminalOracleRegistry.listRegisteredV8Families()].sort(),
      },
      approvalBinders: {
        grantBinders: binderKeys,
        brokerReauthWired: typeof reauthHandler === 'function',
        tier3CoordinatorWired: Boolean(internals.tier3Approvals),
        stateChangeLedgerWired: Boolean(internals.stateChangeApprovals),
        burstApprovalInstancesWired: internals.burstApprovalInstances instanceof Map,
      },
    }
  } finally {
    if (execution) execution.stop()
    await runtime.dispose()
    rmSync(dir, { recursive: true, force: true })
  }
}

export async function emitCapabilityManifest(): Promise<CapabilityManifest> {
  const handlerKeys = discoverProductionHandlerKeys()
  assert.ok(handlerKeys.verifyScriptGated.includes('kovo_verify'), 'ExecWorkerRunner must gate kovo_verify on backendSupportsVerifyScript()')
  const [docker, dood, localJq] = await Promise.all([
    emitBackendSnapshot('docker', handlerKeys),
    emitBackendSnapshot('dood', handlerKeys),
    emitBackendSnapshot('local-jq', handlerKeys),
  ])
  return {
    version: 1,
    backends: {
      docker,
      dood,
      'local-jq': localJq,
    },
  }
}

function diffStringList(prefix: string, expected: readonly string[], actual: readonly string[], diff: CapabilityManifestDiff): void {
  const expSet = new Set(expected)
  const actSet = new Set(actual)
  for (const item of actual) {
    if (!expSet.has(item)) diff.added.push(`${prefix}:${item}`)
  }
  for (const item of expected) {
    if (!actSet.has(item)) diff.removed.push(`${prefix}:${item}`)
  }
}

export function diffCapabilityManifests(expected: CapabilityManifest, actual: CapabilityManifest): CapabilityManifestDiff {
  const diff: CapabilityManifestDiff = { added: [], removed: [], changed: [] }
  const profiles: BackendProfile[] = ['docker', 'dood', 'local-jq']
  for (const profile of profiles) {
    const exp = expected.backends[profile]
    const act = actual.backends[profile]
    if (!exp || !act) {
      diff.changed.push(`backends.${profile}:missing`)
      continue
    }
    if (exp.doodMode !== act.doodMode) diff.changed.push(`${profile}.doodMode:${exp.doodMode}->${act.doodMode}`)
    if (exp.supportsVerifyScript !== act.supportsVerifyScript) {
      diff.changed.push(`${profile}.supportsVerifyScript:${exp.supportsVerifyScript}->${act.supportsVerifyScript}`)
    }
    diffStringList(`${profile}.registeredTools`, exp.registeredTools, act.registeredTools, diff)
    diffStringList(`${profile}.reachableRecipes.core`, exp.reachableRecipes.core, act.reachableRecipes.core, diff)
    diffStringList(`${profile}.reachableRecipes.cut3`, exp.reachableRecipes.cut3, act.reachableRecipes.cut3, diff)
    diffStringList(`${profile}.reachableRecipes.persisted`, exp.reachableRecipes.persisted, act.reachableRecipes.persisted, diff)
    diffStringList(`${profile}.reachableRecipes.wiredSpecKinds`, exp.reachableRecipes.wiredSpecKinds, act.reachableRecipes.wiredSpecKinds, diff)
    diffStringList(`${profile}.oracleFamilies.singleHopRules`, exp.oracleFamilies.singleHopRules, act.oracleFamilies.singleHopRules, diff)
    diffStringList(`${profile}.oracleFamilies.v8Families`, exp.oracleFamilies.v8Families, act.oracleFamilies.v8Families, diff)
    diffStringList(`${profile}.approvalBinders.grantBinders`, exp.approvalBinders.grantBinders, act.approvalBinders.grantBinders, diff)
    for (const flag of ['brokerReauthWired', 'tier3CoordinatorWired', 'stateChangeLedgerWired', 'burstApprovalInstancesWired'] as const) {
      if (exp.approvalBinders[flag] !== act.approvalBinders[flag]) {
        if (exp.approvalBinders[flag] && !act.approvalBinders[flag]) {
          diff.removed.push(`${profile}.approvalBinders.${flag}`)
        } else {
          diff.added.push(`${profile}.approvalBinders.${flag}`)
        }
      }
    }
  }
  return diff
}

test('Composition-root capability manifest matches checked-in fixture across docker, DooD, and local-jq', async () => {
  const actual = await emitCapabilityManifest()
  if (process.env.UPDATE_CAPABILITY_MANIFEST === '1') {
    writeFileSync(fixturePath, `${JSON.stringify(actual, null, 2)}\n`, 'utf8')
  }
  const expected = JSON.parse(readFileSync(fixturePath, 'utf8')) as CapabilityManifest
  const diff = diffCapabilityManifests(expected, actual)

  const removalNotice = diff.removed.length > 0
    ? `\nCAPABILITY REMOVED (requires explicit Contract-change: trailer): ${diff.removed.join(', ')}`
    : ''
  assert.deepEqual(
    actual,
    expected,
    `Capability manifest drifted from tests/fixtures/capability-manifest.json.\n`
      + `added=[${diff.added.join(', ')}] removed=[${diff.removed.join(', ')}] changed=[${diff.changed.join(', ')}]`
      + removalNotice,
  )
})

test('kovo_verify is PRESENT on docker and DooD and ABSENT on local-jq', async () => {
  const manifest = await emitCapabilityManifest()

  assert.equal(manifest.backends.docker.supportsVerifyScript, true)
  assert.equal(manifest.backends.docker.doodMode, 'none')
  assert.ok(manifest.backends.docker.registeredTools.includes('kovo_verify'), 'docker must register kovo_verify')
  assert.ok(!manifest.backends.docker.registeredTools.includes('verify_replay_spec'), 'docker hides legacy verify_replay_spec when kovo_verify is active')

  assert.equal(manifest.backends.dood.supportsVerifyScript, true)
  assert.equal(manifest.backends.dood.doodMode, 'host_bind')
  assert.ok(manifest.backends.dood.registeredTools.includes('kovo_verify'), 'DooD must register kovo_verify')
  assert.ok(!manifest.backends.dood.registeredTools.includes('verify_replay_spec'), 'DooD hides legacy verify_replay_spec when kovo_verify is active')

  assert.equal(manifest.backends['local-jq'].supportsVerifyScript, false)
  assert.ok(!manifest.backends['local-jq'].registeredTools.includes('kovo_verify'), 'local-jq MUST NOT register kovo_verify')
  assert.ok(manifest.backends['local-jq'].registeredTools.includes('verify_replay_spec'), 'local-jq retains legacy verify_replay_spec')
})

test('Reachable recipes, terminal oracle families, and approval binders are complete and aligned', async () => {
  const manifest = await emitCapabilityManifest()
  const unionRecipes = [...new Set([...FLOOR_RECIPE_IDS, ...CUT3_FLOOR_RECIPE_IDS])].sort()

  for (const profile of ['docker', 'dood', 'local-jq'] as const) {
    const snap = manifest.backends[profile]
    assert.deepEqual(snap.reachableRecipes.persisted, unionRecipes, `${profile}: persisted recipe IDs must equal core ∪ cut3`)
    assert.deepEqual(snap.oracleFamilies.v8Families, [...REGISTERED_V8_ORACLE_FAMILIES].sort())
    assert.deepEqual(snap.oracleFamilies.singleHopRules, [...SINGLE_HOP_ORACLE_RULES].sort())
    assert.equal(snap.approvalBinders.brokerReauthWired, true)
    assert.equal(snap.approvalBinders.tier3CoordinatorWired, true)
    assert.equal(snap.approvalBinders.stateChangeLedgerWired, true)
    assert.equal(snap.approvalBinders.burstApprovalInstancesWired, true)
    for (const requiredBinder of ['approvalLeases', 'approvalPolicy', 'canRead', 'isStateChangeApproved', 'scopePolicy']) {
      assert.ok(snap.approvalBinders.grantBinders.includes(requiredBinder), `${profile}: grant missing ${requiredBinder}`)
    }
  }
})

test('diffCapabilityManifests flags removed capabilities for Contract-change review', async () => {
  const base = await emitCapabilityManifest()
  const degraded: CapabilityManifest = structuredClone(base)
  degraded.backends.docker.registeredTools = degraded.backends.docker.registeredTools.filter(t => t !== 'kovo_verify')
  degraded.backends.docker.oracleFamilies.v8Families = degraded.backends.docker.oracleFamilies.v8Families.filter(f => f !== 'dual_tenant_abac')
  degraded.backends.docker.approvalBinders.brokerReauthWired = false

  const diff = diffCapabilityManifests(base, degraded)
  assert.ok(diff.removed.includes('docker.registeredTools:kovo_verify'))
  assert.ok(diff.removed.includes('docker.oracleFamilies.v8Families:dual_tenant_abac'))
  assert.ok(diff.removed.includes('docker.approvalBinders.brokerReauthWired'))
  assert.deepEqual(diff.added, [])
})

test('Unwired-export, runtime import-cycle, and ARCHITECTURE.md citation ratchet passes with zero proof-kernel cycle', () => {
  const res = runUnwiredCheck({ rootDir: repoRoot })
  assert.equal(res.proofKernelCyclePresent, false, 'composite-receipt <-> terminal-oracle-registry must be acyclic')
  assert.deepEqual(res.newCycles, [], `Unexpected new runtime cycles: ${res.newCycles.join('; ')}`)
  assert.deepEqual(res.newUnwiredExports, [], `Unexpected new unwired exports: ${res.newUnwiredExports.map(e => e.key).join(', ')}`)
  assert.deepEqual(res.invalidKeepUnwired, [], `Invalid keep-unwired entries: ${res.invalidKeepUnwired.join(', ')}`)
  assert.deepEqual(res.staleDocCitations, [], `Stale ARCHITECTURE.md citations: ${res.staleDocCitations.map(c => `${c.line}:${c.symbol}`).join(', ')}`)
  assert.equal(res.ok, true)
})

