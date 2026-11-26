/**
 * R2-11 regression tests (`plans/claude_quality_2.md` §11):
 *  1. Canonical `src/server/composite-terminal.ts` resolver parity across `composite-receipt.ts`
 *     (`deriveSignedTerminalOrigin`) and `exec-verify.ts` (`resolveCompositeTerminalExchange` /
 *     `inspectCompositeHostOrigin`), including receipts omitting `terminalExchangeId`.
 *  2. Mandatory `Parity-case:` rule in `scripts/check-contract-change.ts` on confirmation-kernel
 *     diffs (unit tests + real temp git repo CLI tests).
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join, resolve } from 'node:path'
import { test } from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  checkGitRepo,
  evaluateContractChange,
  evaluateParityGate,
  isConfirmationKernelFile,
  isParityCorpusFile,
  loadParityCorpusIds,
  parseParityCaseTrailers,
} from '../scripts/check-contract-change.ts'
import {
  deriveSignedTerminalOrigin,
  signHostRecord,
  type CompositeProofReceipt,
  type HostTranscriptEntry,
} from '../src/server/composite-receipt.ts'
import { resolveCompositeTerminalExchange } from '../src/server/composite-terminal.ts'
import {
  inspectCompositeHostOrigin,
  resolveCompositeTerminalExchange as execResolveCompositeTerminalExchange,
  type HostRecordedExchangeView,
} from '../src/server/exec-verify.ts'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const CHECK_CONTRACT_TS = join(REPO_ROOT, 'scripts/check-contract-change.ts')
const SIGNING_KEY = 'r2-11-unit-test-signing-key-123456'

function makeTempGitRepo(t: { after: (fn: () => void) => void }, prefix: string): {
  repo: string
  git: (...args: string[]) => string
} {
  const repo = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(repo, { recursive: true, force: true }))
  const git = (...args: string[]) =>
    execFileSync('git', args, { cwd: repo, encoding: 'utf8', stdio: ['ignore', 'pipe', 'pipe'] }).trim()
  git('init', '-b', 'main')
  git('config', 'user.email', 'r211-test@example.invalid')
  git('config', 'user.name', 'R211 Tester')
  return { repo, git }
}

function makeTranscriptEntry(
  exchangeId: string,
  arm: 'control' | 'probe' | 'setup',
  status: number,
  origin?: string,
): HostTranscriptEntry {
  const base: HostTranscriptEntry = {
    exchangeId,
    ...(origin !== undefined ? { origin } : {}),
    timestampMs: 1_700_000_000_000,
    actorPersona: 'member_a',
    cleanSession: true,
    step: {
      id: exchangeId,
      arm,
      method: 'GET',
      route: '/v1/exports/download',
      pathAndQuery: '/v1/exports/download',
      status,
      actor: { handle: 'member_a', role: 'member', tenant: 'tenant-a', auth: 'bearer', sameSite: null },
      body: '{"ok":true}',
      responseHeaders: { 'content-type': 'application/json' },
    },
  }
  return { ...base, hostSignature: signHostRecord(base, SIGNING_KEY) }
}

function toView(e: HostTranscriptEntry): HostRecordedExchangeView {
  return {
    exchangeId: e.exchangeId,
    origin: e.origin ?? '',
    method: e.step.method,
    pathAndQuery: e.step.pathAndQuery ?? e.step.route ?? '',
    status: e.step.status,
    sessionRole: e.step.arm,
  }
}

// ============================================================================
// 1. Canonical src/server/composite-terminal.ts resolver & cross-module parity
// ============================================================================

test('composite-terminal: deterministic precedence and exact parity between composite-receipt.ts and exec-verify.ts', () => {
  const originA = 'http://127.0.0.1:4510'
  const originB = 'http://127.0.0.1:4511'

  const ctrl = makeTranscriptEntry('ex_ctrl', 'control', 403, originA)
  const prbFail = makeTranscriptEntry('ex_prb_500', 'probe', 500, originA)
  const prbOk1 = makeTranscriptEntry('ex_prb_200_a', 'probe', 200, originA)
  const prbOk2 = makeTranscriptEntry('ex_prb_200_b', 'probe', 201, originB)
  const ctrlNoOrigin = makeTranscriptEntry('ex_ctrl_noorig', 'control', 200, '')
  const setupWithOrigin = makeTranscriptEntry('ex_setup_orig', 'setup', 200, originA)

  const makeReceipt = (exchangeIds: string[], terminalExchangeId?: string, declaredOrigin = originB): CompositeProofReceipt => ({
    chainId: 'r2-11-term-test',
    terminalVulnClass: 'bola',
    hops: [
      {
        hopId: 'hop_term',
        surface: 'http',
        target: { origin: declaredOrigin, method: 'GET', pathAndQuery: '/v1/exports/download' },
        exchangeIds,
        oobEventIds: [],
        browserTraceIds: [],
        claimedDelta: 'Terminal exchange resolution test.',
        producedCapabilities: [],
        consumedCapabilities: [],
      },
    ],
    causalEdges: [],
    terminalImpact: {
      terminalHopId: 'hop_term',
      ...(terminalExchangeId ? { terminalExchangeId } : {}),
      claimedImpact: 'Terminal exchange resolution test.',
      summary: 'Terminal exchange resolution test.',
      preChainControlExchangeIds: [],
      postChainReadbackExchangeIds: [],
    },
    replayMode: 'fresh_clean_replay',
  })

  const allEntries = [ctrl, prbFail, prbOk1, prbOk2, ctrlNoOrigin, setupWithOrigin]
  const viewMap = new Map(allEntries.map(e => [e.exchangeId, toView(e)]))

  // 1) Explicit terminalExchangeId wins over later probe 2xx.
  const explicitRec = makeReceipt(['ex_ctrl', 'ex_prb_200_a', 'ex_prb_200_b'], 'ex_prb_200_a', originA)
  assert.equal(resolveCompositeTerminalExchange(explicitRec, allEntries)?.exchangeId, 'ex_prb_200_a')
  assert.equal(execResolveCompositeTerminalExchange(explicitRec, viewMap)?.exchangeId, 'ex_prb_200_a')
  assert.equal(deriveSignedTerminalOrigin(explicitRec, allEntries), originA)

  // 2) Omitted terminalExchangeId selects the LAST 2xx probe exchange.
  const omittedRec = makeReceipt(['ex_ctrl', 'ex_prb_200_a', 'ex_prb_200_b', 'ex_prb_500'], undefined, originB)
  assert.equal(resolveCompositeTerminalExchange(omittedRec, allEntries)?.exchangeId, 'ex_prb_200_b')
  assert.equal(execResolveCompositeTerminalExchange(omittedRec, viewMap)?.exchangeId, 'ex_prb_200_b')
  assert.equal(deriveSignedTerminalOrigin(omittedRec, allEntries), originB)
  const inspected = inspectCompositeHostOrigin(omittedRec, viewMap)
  assert.equal(inspected.ok, true)
  if (inspected.ok) {
    assert.equal(inspected.origin, originB)
    assert.equal(inspected.terminalExchange.exchangeId, 'ex_prb_200_b')
  }

  // 3) No 2xx probe -> selects last probe exchange.
  const non2xxProbeRec = makeReceipt(['ex_ctrl', 'ex_prb_500'], undefined, originA)
  assert.equal(resolveCompositeTerminalExchange(non2xxProbeRec, allEntries)?.exchangeId, 'ex_prb_500')
  assert.equal(execResolveCompositeTerminalExchange(non2xxProbeRec, viewMap)?.exchangeId, 'ex_prb_500')

  // 4) No probe exchange -> selects last exchange with non-empty signed origin (resolving the old divergence!).
  const noProbeRec = makeReceipt(['ex_setup_orig', 'ex_ctrl_noorig'], undefined, originA)
  assert.equal(resolveCompositeTerminalExchange(noProbeRec, allEntries)?.exchangeId, 'ex_setup_orig')
  assert.equal(execResolveCompositeTerminalExchange(noProbeRec, viewMap)?.exchangeId, 'ex_setup_orig')
  assert.equal(deriveSignedTerminalOrigin(noProbeRec, allEntries), originA)
  const inspectedNoProbe = inspectCompositeHostOrigin(noProbeRec, viewMap)
  assert.equal(inspectedNoProbe.ok, true)
  if (inspectedNoProbe.ok) {
    assert.equal(inspectedNoProbe.origin, originA)
    assert.equal(inspectedNoProbe.terminalExchange.exchangeId, 'ex_setup_orig')
  }

  // 5) No exchange has origin -> returns last exchange deterministically and origin resolves to null.
  const emptyOriginRec = makeReceipt(['ex_ctrl_noorig'], undefined, originA)
  assert.equal(resolveCompositeTerminalExchange(emptyOriginRec, allEntries)?.exchangeId, 'ex_ctrl_noorig')
  assert.equal(deriveSignedTerminalOrigin(emptyOriginRec, allEntries), null)
  assert.equal(inspectCompositeHostOrigin(emptyOriginRec, viewMap).ok, false)
})

// ============================================================================
// 2. Mandatory Parity-case: rule in scripts/check-contract-change.ts
// ============================================================================

test('check-contract-change identifies all confirmation-kernel files and loads checked-in parity corpus IDs', () => {
  const kernelFiles = [
    'src/server/replay-verifier.ts',
    'src/server/verify-claims.ts',
    'src/server/proof-receipt.ts',
    'src/server/floor-recipes.ts',
    'src/server/floor-recipe-engine.ts',
    'src/server/composite-receipt.ts',
    'src/server/composite-terminal.ts',
    'src/server/oracle-invariants.ts',
    'src/server/exec-verify.ts',
    'src/server/v8-oracle-families.ts',
    'src/server/v8-oracle-hydrate.ts',
    'src/server/verify-support.ts',
  ]
  for (const f of kernelFiles) {
    assert.equal(isConfirmationKernelFile(f), true, `expected ${f} to match confirmation-kernel classifier`)
  }
  assert.equal(isConfirmationKernelFile('src/server/floor-recipe.test.ts'), false)
  assert.equal(isConfirmationKernelFile('src/server/ui-server.ts'), false)
  assert.equal(isConfirmationKernelFile('src/domain.ts'), false)

  assert.equal(isParityCorpusFile('tests/parity/corpus/boolean-differential-tp.json'), true)
  assert.equal(isParityCorpusFile('tests/parity/corpus/README.md'), false)
  assert.equal(isParityCorpusFile('tests/path-parity.test.ts'), false)

  const corpusIds = loadParityCorpusIds(REPO_ROOT)
  assert.ok(corpusIds.has('cross-tenant-bola-tp'))
  assert.ok(corpusIds.has('composite-no-terminal-id-tp'))
  assert.ok(corpusIds.has('boolean-integer-coercion-fp'))

  assert.deepEqual(
    parseParityCaseTrailers('fix kernel\n\nParity-case: composite-no-terminal-id-tp — exercises terminal fallback\nParity-case: boolean-differential-tp\n'),
    ['composite-no-terminal-id-tp', 'boolean-differential-tp'],
  )
})

test('evaluateParityGate / evaluateContractChange enforce corpus touch or valid existing Parity-case: <id> on kernel diffs', () => {
  const knownIds = new Set(['cross-tenant-bola-tp', 'composite-no-terminal-id-tp'])
  const kernelOnlyDiff = [
    'diff --git a/src/server/proof-receipt.ts b/src/server/proof-receipt.ts',
    '--- a/src/server/proof-receipt.ts',
    '+++ b/src/server/proof-receipt.ts',
    '@@ -100,3 +100,3 @@',
    '-  return false',
    '+  return true',
  ].join('\n')

  // 1) Missing corpus touch and missing Parity-case trailer -> FAIL in strict, WARN in warn mode.
  const failStrict = evaluateContractChange({
    diffText: kernelOnlyDiff,
    commitMessages: 'fix(receipt): tighten check\n',
    mode: 'strict',
    sourceLabel: 'test',
    knownParityCaseIds: knownIds,
  })
  assert.equal(failStrict.ok, false)
  assert.equal(failStrict.parity?.required, true)
  assert.equal(failStrict.parity?.ok, false)

  const warnDirty = evaluateParityGate({
    diffText: kernelOnlyDiff,
    commitMessages: '',
    mode: 'warn',
    knownParityCaseIds: knownIds,
  })
  assert.equal(warnDirty.ok, true)
  assert.equal(warnDirty.warned, true)

  // 2) Fabricated / nonexistent Parity-case ID -> FAIL closed!
  const invalidId = evaluateContractChange({
    diffText: kernelOnlyDiff,
    commitMessages: 'fix(receipt): tighten check\n\nParity-case: does-not-exist-in-corpus\n',
    mode: 'strict',
    sourceLabel: 'test',
    knownParityCaseIds: knownIds,
  })
  assert.equal(invalidId.ok, false)
  assert.deepEqual(invalidId.parity?.invalidParityCaseIds, ['does-not-exist-in-corpus'])

  // 3) Valid existing Parity-case ID -> PASS!
  const validId = evaluateContractChange({
    diffText: kernelOnlyDiff,
    commitMessages: 'fix(receipt): tighten check\n\nParity-case: composite-no-terminal-id-tp\n',
    mode: 'strict',
    sourceLabel: 'test',
    knownParityCaseIds: knownIds,
  })
  assert.equal(validId.ok, true)
  assert.deepEqual(validId.parity?.validParityCaseIds, ['composite-no-terminal-id-tp'])

  // 4) Diff touching tests/parity/corpus/*.json -> PASS without Parity-case trailer!
  const kernelPlusCorpusDiff = [
    kernelOnlyDiff,
    'diff --git a/tests/parity/corpus/new-case-tp.json b/tests/parity/corpus/new-case-tp.json',
    '--- /dev/null',
    '+++ b/tests/parity/corpus/new-case-tp.json',
    '@@ -0,0 +1,1 @@',
    '+{"id":"new-case-tp"}',
  ].join('\n')
  const corpusPass = evaluateContractChange({
    diffText: kernelPlusCorpusDiff,
    commitMessages: 'fix(receipt): add corpus case\n',
    mode: 'strict',
    sourceLabel: 'test',
    knownParityCaseIds: knownIds,
  })
  assert.equal(corpusPass.ok, true)
  assert.deepEqual(corpusPass.parity?.corpusFilesTouched, ['tests/parity/corpus/new-case-tp.json'])

  // 5) Deleting a corpus file must NOT satisfy the parity rule!
  const deletedCorpusDiff = [
    kernelOnlyDiff,
    'diff --git a/tests/parity/corpus/old-case.json b/tests/parity/corpus/old-case.json',
    '--- a/tests/parity/corpus/old-case.json',
    '+++ /dev/null',
    '@@ -1,1 +0,0 @@',
    '-{"id":"old-case"}',
  ].join('\n')
  const deletedFail = evaluateParityGate({
    diffText: deletedCorpusDiff,
    commitMessages: 'delete corpus case\n',
    mode: 'strict',
    knownParityCaseIds: knownIds,
  })
  assert.equal(deletedFail.ok, false)
})

test('check-contract-change CLI enforces Parity-case: <id> on real temp git repo kernel commits', (t) => {
  const { repo, git } = makeTempGitRepo(t, 'r211-parity-cli-')
  mkdirSync(join(repo, 'src/server'), { recursive: true })
  mkdirSync(join(repo, 'tests/parity/corpus'), { recursive: true })

  writeFileSync(join(repo, 'src/server/composite-terminal.ts'), 'export const v = 1\n')
  writeFileSync(
    join(repo, 'tests/parity/corpus/sample-case-tp.json'),
    JSON.stringify({ id: 'sample-case-tp' }) + '\n',
  )
  git('add', '.')
  git('commit', '-m', 'init')

  // Edit confirmation-kernel file without touching corpus and without Parity-case trailer -> CLI FAIL!
  writeFileSync(join(repo, 'src/server/composite-terminal.ts'), 'export const v = 2\n')
  git('add', 'src/server/composite-terminal.ts')
  git('commit', '-m', 'edit kernel without parity reference')

  const failNoTrailer = spawnSync(process.execPath, [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'], { encoding: 'utf8' })
  assert.equal(failNoTrailer.status, 1, 'kernel commit without corpus diff or Parity-case must fail')
  assert.ok(failNoTrailer.stderr.includes('Parity-case:'))

  // Amend with nonexistent Parity-case ID -> CLI FAIL!
  git('commit', '--amend', '-m', 'edit kernel\n\nParity-case: fabricated-id-999')
  const failBadId = spawnSync(process.execPath, [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'], { encoding: 'utf8' })
  assert.equal(failBadId.status, 1, 'nonexistent Parity-case ID must fail')
  assert.ok(failBadId.stderr.includes('fabricated-id-999'))

  // Amend with existing Parity-case ID -> CLI PASS!
  git('commit', '--amend', '-m', 'edit kernel\n\nParity-case: sample-case-tp')
  const passValidId = spawnSync(process.execPath, [CHECK_CONTRACT_TS, '--root', repo, '--base', 'HEAD~1'], { encoding: 'utf8' })
  assert.equal(passValidId.status, 0, `valid Parity-case ID must pass: ${passValidId.stderr}`)
  assert.ok(passValidId.stdout.includes('parity-gate'))
  assert.equal(checkGitRepo({ rootDir: repo, baseRef: 'HEAD~1' }).ok, true)
})
