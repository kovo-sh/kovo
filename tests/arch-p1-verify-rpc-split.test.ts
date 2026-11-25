/**
 * Architectural regression test for P1 #2 (`verify-rpc.ts` decomposition):
 *
 *  1. LOC ceilings: `verify-rpc.ts` and every extracted `verify-*.ts` module stay <= 2,300 LOC.
 *  2. Strictly acyclic import graph across all `src/server/verify-*.ts` modules (including
 *     type-only imports and re-exports) with the intended downward layering:
 *       verify-claims.ts (leaf) <- verify-prove-handlers.ts / verify-runner.ts <- verify-rpc.ts
 *  3. 100% public runtime export parity from `src/server/verify-rpc.ts` with identity
 *     preservation to the canonical definitions in `verify-claims.ts` and `verify-runner.ts`.
 */
import test from 'node:test'
import assert from 'node:assert/strict'
import { readdirSync, readFileSync } from 'node:fs'
import { dirname, join, resolve } from 'node:path'
import { fileURLToPath } from 'node:url'

import * as verifyRpc from '../src/server/verify-rpc.ts'
import * as verifyClaims from '../src/server/verify-claims.ts'
import * as verifyProveHandlers from '../src/server/verify-prove-handlers.ts'
import * as verifyRunner from '../src/server/verify-runner.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const SERVER_DIR = join(REPO_ROOT, 'src/server')
const LOC_CEILING = 2300

const SPLIT_MODULES = [
  'verify-rpc.ts',
  'verify-claims.ts',
  'verify-prove-handlers.ts',
  'verify-runner.ts',
] as const

function countLoc(filePath: string): number {
  return readFileSync(filePath, 'utf8').trimEnd().split('\n').length
}

function parseVerifyImports(filePath: string): string[] {
  const src = readFileSync(filePath, 'utf8')
  const deps = new Set<string>()
  // Matches static `import ... from './verify-*.ts'`, `export ... from './verify-*.ts'`,
  // and dynamic `import('./verify-*.ts')`.
  const re = /(?:from\s+|import\s*\(\s*)['"]\.\/(verify-[^'"]+\.ts)['"]/g
  let match: RegExpExecArray | null
  while ((match = re.exec(src)) !== null) {
    deps.add(match[1]!)
  }
  return [...deps]
}

test('verify-rpc.ts and every extracted sibling module stay <= 2,300 LOC', () => {
  for (const mod of SPLIT_MODULES) {
    const loc = countLoc(join(SERVER_DIR, mod))
    assert.ok(loc <= LOC_CEILING, `${mod} is ${loc} LOC (ceiling is <= ${LOC_CEILING} LOC)`)
    assert.ok(loc > 0, `${mod} must be non-empty`)
  }
})

test('import graph across src/server/verify-*.ts is strictly acyclic and respects downward layering', () => {
  const verifyFiles = readdirSync(SERVER_DIR)
    .filter(name => /^verify-.*\.ts$/.test(name))
    .sort()
  for (const mod of SPLIT_MODULES) {
    assert.ok(verifyFiles.includes(mod), `expected split module ${mod} in src/server/`)
  }

  const graph = new Map<string, string[]>()
  for (const file of verifyFiles) {
    graph.set(file, parseVerifyImports(join(SERVER_DIR, file)))
  }

  // 3-color DFS cycle check across ALL verify-*.ts files (value + type imports + re-exports).
  const state = new Map<string, 'visiting' | 'visited'>()
  const stack: string[] = []
  function dfs(node: string): void {
    state.set(node, 'visiting')
    stack.push(node)
    for (const dep of graph.get(node) ?? []) {
      const depState = state.get(dep)
      if (depState === 'visiting') {
        const cycleStart = stack.indexOf(dep)
        assert.fail(`Circular import detected in verify-*.ts: ${[...stack.slice(cycleStart), dep].join(' -> ')}`)
      }
      if (!depState) dfs(dep)
    }
    stack.pop()
    state.set(node, 'visited')
  }
  for (const file of verifyFiles) {
    if (!state.has(file)) dfs(file)
  }

  // Layering invariants:
  const claimsDeps = graph.get('verify-claims.ts') ?? []
  assert.deepEqual(
    claimsDeps.filter(d => d !== 'verify-support.ts'),
    [],
    `verify-claims.ts must be the leaf (only verify-support.ts allowed), got: ${claimsDeps.join(', ')}`,
  )

  const proveDeps = graph.get('verify-prove-handlers.ts') ?? []
  assert.ok(proveDeps.includes('verify-claims.ts'), 'verify-prove-handlers.ts must depend on verify-claims.ts')
  assert.equal(proveDeps.includes('verify-rpc.ts'), false, 'verify-prove-handlers.ts must not import verify-rpc.ts')
  assert.equal(proveDeps.includes('verify-runner.ts'), false, 'verify-prove-handlers.ts must not import verify-runner.ts')

  const runnerDeps = graph.get('verify-runner.ts') ?? []
  assert.ok(runnerDeps.includes('verify-claims.ts'), 'verify-runner.ts must depend on verify-claims.ts')
  assert.equal(runnerDeps.includes('verify-rpc.ts'), false, 'verify-runner.ts must not import verify-rpc.ts')
  assert.equal(runnerDeps.includes('verify-prove-handlers.ts'), false, 'verify-runner.ts must not import verify-prove-handlers.ts')

  const rpcDeps = graph.get('verify-rpc.ts') ?? []
  assert.ok(rpcDeps.includes('verify-claims.ts'), 'verify-rpc.ts must wire verify-claims.ts')
  assert.ok(rpcDeps.includes('verify-prove-handlers.ts'), 'verify-rpc.ts must wire verify-prove-handlers.ts')
  assert.ok(rpcDeps.includes('verify-runner.ts'), 'verify-rpc.ts must wire verify-runner.ts')
})

test('verify-rpc.ts preserves 100% public runtime export parity with canonical sibling modules', () => {
  const expectedRuntimeExports: Record<string, string> = {
    VERIFY_RPC_CONTAINER_DIR: 'string',
    VERIFY_RPC_SOCKET_NAME: 'string',
    VERIFY_RPC_TOKEN_NAME: 'string',
    VERIFY_RPC_CONTEXT_NAME: 'string',
    VERIFY_RPC_SOCKET_ENV: 'string',
    VERIFY_RPC_TOKEN_ENV: 'string',
    VERIFY_RPC_CONTEXT_ENV: 'string',
    VERIFY_NONCE_ENV: 'string',
    VERIFY_RESULT_ENV: 'string',
    VERIFY_RPC_HEADER: 'string',
    VERIFY_NONCE_HEADER: 'string',
    VERIFY_RESULT_MARKER: 'string',
    TranscriptStore: 'function',
    normalizeDynamic: 'function',
    parseVerifyScriptResult: 'function',
    mannWhitneyU: 'function',
    describeMissingEvidence: 'function',
    evaluateClaims: 'function',
    causalFingerprints: 'function',
    VerifyRpcServer: 'function',
    KOVO_VERIFY_STDERR_PREVIEW_MAX_CHARS: 'number',
    KOVO_VERIFY_USAGE_HINT: 'string',
    redactStderrPreview: 'function',
    prepareVerifyScript: 'function',
    verifyScript: 'function',
    createLocalAttemptFactory: 'function',
    runCandidateLocally: 'function',
  }

  const actualKeys = Object.keys(verifyRpc).sort()
  const expectedKeys = Object.keys(expectedRuntimeExports).sort()
  assert.deepEqual(actualKeys, expectedKeys, 'verify-rpc.ts runtime export set must match pre-split public surface')

  const rpcRecord = verifyRpc as Record<string, unknown>
  for (const [name, expectedType] of Object.entries(expectedRuntimeExports)) {
    assert.equal(typeof rpcRecord[name], expectedType, `verify-rpc.ts export ${name} must have typeof ${expectedType}`)
  }

  // Identity parity: re-exported symbols are exact references to the extracted modules (no duplication).
  const claimsSymbols = [
    'VERIFY_RPC_CONTAINER_DIR',
    'VERIFY_RPC_SOCKET_NAME',
    'VERIFY_RPC_TOKEN_NAME',
    'VERIFY_RPC_CONTEXT_NAME',
    'VERIFY_RPC_SOCKET_ENV',
    'VERIFY_RPC_TOKEN_ENV',
    'VERIFY_RPC_CONTEXT_ENV',
    'VERIFY_NONCE_ENV',
    'VERIFY_RESULT_ENV',
    'VERIFY_RPC_HEADER',
    'VERIFY_NONCE_HEADER',
    'VERIFY_RESULT_MARKER',
    'TranscriptStore',
    'normalizeDynamic',
    'parseVerifyScriptResult',
    'mannWhitneyU',
    'describeMissingEvidence',
    'evaluateClaims',
    'causalFingerprints',
  ] as const
  for (const name of claimsSymbols) {
    assert.strictEqual(rpcRecord[name], (verifyClaims as Record<string, unknown>)[name], `${name} must re-export verify-claims.ts`)
  }

  const runnerSymbols = [
    'KOVO_VERIFY_STDERR_PREVIEW_MAX_CHARS',
    'KOVO_VERIFY_USAGE_HINT',
    'redactStderrPreview',
    'prepareVerifyScript',
    'verifyScript',
    'runCandidateLocally',
  ] as const
  for (const name of runnerSymbols) {
    assert.strictEqual(rpcRecord[name], (verifyRunner as Record<string, unknown>)[name], `${name} must re-export verify-runner.ts`)
  }

  // All 6 host `prove.*` executors live in verify-prove-handlers.ts.
  for (const handler of [
    'handleProveAccessBoundary',
    'handleProvePersistedMutation',
    'handleProveDifferential',
    'handleProveOob',
    'handleProveRace',
    'handleProveInjection',
  ] as const) {
    assert.equal(typeof (verifyProveHandlers as Record<string, unknown>)[handler], 'function', `verify-prove-handlers.ts must export ${handler}`)
  }
})
