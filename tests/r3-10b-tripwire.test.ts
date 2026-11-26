// @fixes R3-10
/**
 * R3-10 Stream B/C behavioral guard suite:
 *   1. `scripts/parallel-pulse.sh` repeat-patch escalation tripwire (`ESCALATE ARCHITECTURE MOVE`)
 *      over recent fix commits and cross-round `Fixes:` history (advisory only — always exits 0).
 *   2. `scripts/parallel-pulse.sh` deletion-debt audit (`plans/STREAM-BACKLOG.md` `## Deletion Debt`)
 *      with overdue detection, plus net `src/server` LOC reporting per landed stream.
 *   3. `src/server/broker.ts` Stage-2 legacy bucket retirement: direct re-export identity with
 *      `src/server/target-load-policy.ts` and unified apex/IP aggregate bucket pacing & disposal.
 */
import assert from 'node:assert/strict'
import { execFileSync, spawnSync } from 'node:child_process'
import { mkdirSync, mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { dirname, join, resolve } from 'node:path'
import test from 'node:test'
import { fileURLToPath } from 'node:url'
import {
  brokerExternalApexRpsCap,
  brokerPerOriginConcurrencyCap,
  brokerPerOriginRpsCap,
  externalApexBucketKey,
  RequestBroker,
} from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import {
  resolveBrokerPerOriginConcurrencyCap,
  resolveBrokerPerOriginRpsCap,
  resolveExternalApexBucketKey,
  resolveExternalApexRpsCap,
} from '../src/server/target-load-policy.ts'

const REPO_ROOT = resolve(dirname(fileURLToPath(import.meta.url)), '..')
const PARALLEL_PULSE_SH = join(REPO_ROOT, 'scripts', 'parallel-pulse.sh')

function makeTempDir(t: test.TestContext, prefix: string): string {
  const dir = mkdtempSync(join(tmpdir(), prefix))
  t.after(() => rmSync(dir, { recursive: true, force: true }))
  return dir
}

function git(cwd: string, args: string[]): string {
  return execFileSync('git', ['-C', cwd, ...args], {
    encoding: 'utf8',
    stdio: ['ignore', 'pipe', 'pipe'],
  }).trim()
}

function initTempGitRepo(dir: string): void {
  execFileSync('git', ['init', '-b', 'main', dir], { stdio: 'ignore' })
  git(dir, ['config', 'user.email', 'qa@example.test'])
  git(dir, ['config', 'user.name', 'QA Bot'])
}

function runPulse(
  cwd: string,
  args: string[],
  envPatch: Record<string, string> = {},
): { status: number; stdout: string; stderr: string } {
  const res = spawnSync('bash', [PARALLEL_PULSE_SH, ...args], {
    cwd,
    env: {
      ...process.env,
      KOVO_PULSE_SKIP_CI_CHECK: '1',
      ...envPatch,
    },
    encoding: 'utf8',
  })
  return {
    status: res.status ?? 1,
    stdout: res.stdout ?? '',
    stderr: res.stderr ?? '',
  }
}

interface PulseJsonOutput {
  repeatPatchWindow: number
  repeatPatchThreshold: number
  repeatPatchEscalations: Array<{
    file: string
    subsystem: string
    recentFixCount: number
    historyFixCommitCount: number
    fixesIds: string[]
    crossRound: boolean
    activeStreams: string[]
    commits: string[]
    reasons: string[]
  }>
  deletionDebt: {
    path: string
    open: number
    overdue: number
    retired: number
    entries: Array<{
      id: string
      legacyPath: string
      replacement: string
      owner: string
      target: string
      expiryDate: string | null
      status: string
      retired: boolean
      overdue: boolean
    }>
  }
  netServerLoc: {
    baseRef: string | null
    window: number
    totalAdded: number
    totalDeleted: number
    totalNet: number
    streams: Array<{
      sha: string
      subject: string
      added: number
      deleted: number
      net: number
    }>
  }
}

// ---------------------------------------------------------------------------
// 1. Repeat-patch escalation tripwire (recent window + cross-round Fixes:)
// ---------------------------------------------------------------------------

test('R3-10b.1: parallel-pulse.sh emits ESCALATE ARCHITECTURE MOVE at >=2 fix commits (recent & cross-round) and never blocks', (t) => {
  const repo = makeTempDir(t, 'kovo-r3-10b-tripwire-')
  initTempGitRepo(repo)
  mkdirSync(join(repo, 'src', 'server'), { recursive: true })
  mkdirSync(join(repo, 'tests'), { recursive: true })

  const hotFile = join(repo, 'src', 'server', 'hot-oracle.ts')
  const cleanFile = join(repo, 'src', 'server', 'clean-helper.ts')
  writeFileSync(hotFile, 'export const v = 1\n')
  writeFileSync(cleanFile, 'export const ok = true\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'chore: initial files'])

  // 1st fix commit on hot-oracle.ts -> still below threshold (2), zero escalations.
  writeFileSync(hotFile, 'export const v = 2\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'fix(oracle): guard edge case\n\nFixes: R2-11'])

  // Non-fix chore commits and test edits MUST NOT trigger repeat-patch escalation.
  writeFileSync(hotFile, 'export const v = 2 // comment\n')
  writeFileSync(join(repo, 'tests', 'hot.test.ts'), 'export const t = 1\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'chore: formatting and test update'])

  const beforeText = runPulse(repo, [])
  assert.equal(beforeText.status, 0, beforeText.stderr)
  assert.equal(beforeText.stdout.includes('ESCALATE ARCHITECTURE MOVE'), false, `unexpected alert: ${beforeText.stdout}`)
  assert.match(beforeText.stdout, /repeat-patch tripwire \(last 30 commits\): ok \(0 escalations\)/)

  const beforeJson = runPulse(repo, ['--json'])
  assert.equal(beforeJson.status, 0, beforeJson.stderr)
  const parsedBefore = JSON.parse(beforeJson.stdout) as PulseJsonOutput
  assert.equal(parsedBefore.repeatPatchEscalations.length, 0)

  // 2nd fix commit on hot-oracle.ts across rounds (Fixes: R3-11) -> MUST emit ESCALATE ARCHITECTURE MOVE and exit 0.
  writeFileSync(hotFile, 'export const v = 3\nexport const w = 4\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'fix(oracle): second point patch\n\nFixes: R3-11'])

  const afterText = runPulse(repo, [])
  assert.equal(afterText.status, 0, `tripwire must escalate without blocking: ${afterText.stderr}`)
  assert.match(afterText.stdout, /ESCALATE ARCHITECTURE MOVE:\s+src\/server\/hot-oracle\.ts/)
  assert.match(afterText.stdout, /AGENTS\.md Systemic Fixes rule 6/)

  const afterJson = runPulse(repo, ['--json'])
  assert.equal(afterJson.status, 0, afterJson.stderr)
  const parsedAfter = JSON.parse(afterJson.stdout) as PulseJsonOutput
  assert.equal(parsedAfter.repeatPatchEscalations.length, 1)
  const item = parsedAfter.repeatPatchEscalations[0]!
  assert.equal(item.file, 'src/server/hot-oracle.ts')
  assert.equal(item.recentFixCount, 2)
  assert.equal(item.crossRound, true)
  assert.deepEqual(item.fixesIds, ['R2-11', 'R3-11'])

  // Even when the 1st fix falls outside the recent window (window=1), cross-round Fixes: history MUST still escalate.
  const crossRoundOnly = runPulse(repo, ['--json'], {
    KOVO_PULSE_REPEAT_WINDOW: '1',
    KOVO_PULSE_HISTORY_LIMIT: '50',
  })
  assert.equal(crossRoundOnly.status, 0, crossRoundOnly.stderr)
  const parsedCross = JSON.parse(crossRoundOnly.stdout) as PulseJsonOutput
  assert.equal(parsedCross.repeatPatchEscalations.length, 1)
  assert.equal(parsedCross.repeatPatchEscalations[0]!.recentFixCount, 1)
  assert.equal(parsedCross.repeatPatchEscalations[0]!.crossRound, true)
})

// ---------------------------------------------------------------------------
// 2. Deletion-debt table parsing, overdue detection, and net src/server LOC
// ---------------------------------------------------------------------------

test('R3-10b.2: parallel-pulse.sh audits plans/STREAM-BACKLOG.md Deletion Debt (including overdue) and reports net src/server LOC', (t) => {
  const repo = makeTempDir(t, 'kovo-r3-10b-debt-')
  initTempGitRepo(repo)
  mkdirSync(join(repo, 'src', 'server'), { recursive: true })
  mkdirSync(join(repo, 'plans'), { recursive: true })

  writeFileSync(
    join(repo, 'plans', 'STREAM-BACKLOG.md'),
    [
      '# Stream backlog',
      '',
      '## Deletion Debt',
      '',
      '| ID | Legacy Path / Symbol | Replacement | Owner | Target Milestone / Expiry | Status |',
      '|---|---|---|---|---|---|',
      '| `DD-01` | `src/server/old-a.ts` | `src/server/new-a.ts` | `stream-a` | `R3-10 (2026-11-26)` | `retired` |',
      '| `DD-02` | `src/server/old-b.ts` | `src/server/new-b.ts` | `stream-b` | `v8-m0 (2026-01-15)` | `open` |',
      '| `DD-03` | `src/server/old-c.ts` | `src/server/new-c.ts` | `stream-c` | `v8-m1 (2027-06-01)` | `open` |',
      '',
    ].join('\n'),
  )
  writeFileSync(join(repo, 'src', 'server', 'sample.ts'), 'export const a = 1\nexport const b = 2\nexport const c = 3\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'feat: add sample server file'])

  // Shrink sample.ts by 2 lines in a follow-up commit to verify negative net LOC accounting.
  writeFileSync(join(repo, 'src', 'server', 'sample.ts'), 'export const a = 1\n')
  git(repo, ['add', '-A'])
  git(repo, ['commit', '-m', 'refactor: retire legacy lines'])

  // Fixed epoch: 2026-11-26T12:00:00Z -> DD-02 (2026-01-15) is overdue, DD-03 (2027-06-01) is open not overdue.
  const fixedNowEpoch = String(Math.floor(Date.parse('2026-11-26T12:00:00Z') / 1000))
  const textRes = runPulse(repo, [], { KOVO_PULSE_NOW_EPOCH: fixedNowEpoch })
  assert.equal(textRes.status, 0, textRes.stderr)
  assert.match(textRes.stdout, /deletion debt \(plans\/STREAM-BACKLOG\.md\): 2 open, 1 overdue, 1 retired/)
  assert.match(textRes.stdout, /ACTION DELETION DEBT OVERDUE:\s+DD-02/)
  assert.match(textRes.stdout, /net src\/server LOC \(last 2 landed commits on main\): \+1 \(\+3\/-2\)/)

  const jsonRes = runPulse(repo, ['--json'], { KOVO_PULSE_NOW_EPOCH: fixedNowEpoch })
  assert.equal(jsonRes.status, 0, jsonRes.stderr)
  const parsed = JSON.parse(jsonRes.stdout) as PulseJsonOutput
  assert.equal(parsed.deletionDebt.open, 2)
  assert.equal(parsed.deletionDebt.overdue, 1)
  assert.equal(parsed.deletionDebt.retired, 1)
  assert.equal(parsed.deletionDebt.entries.find(e => e.id === 'DD-02')?.overdue, true)
  assert.equal(parsed.deletionDebt.entries.find(e => e.id === 'DD-03')?.overdue, false)
  assert.equal(parsed.netServerLoc.totalAdded, 3)
  assert.equal(parsed.netServerLoc.totalDeleted, 2)
  assert.equal(parsed.netServerLoc.totalNet, 1)
  assert.equal(parsed.netServerLoc.streams[0]?.net, -2)

  // Verify the real repository's plans/STREAM-BACKLOG.md Deletion Debt table parses cleanly in pulse.
  const repoPulse = runPulse(REPO_ROOT, ['--json'])
  assert.equal(repoPulse.status, 0, repoPulse.stderr)
  const repoParsed = JSON.parse(repoPulse.stdout) as PulseJsonOutput
  assert.ok(repoParsed.deletionDebt.entries.length >= 2, 'real STREAM-BACKLOG.md must declare Deletion Debt rows')
  assert.equal(repoParsed.deletionDebt.entries.find(e => e.id === 'DD-01')?.retired, true)
  assert.ok(repoParsed.deletionDebt.open >= 1)
  assert.ok(repoParsed.netServerLoc.streams.length >= 1)
})

// ---------------------------------------------------------------------------
// 3. Stage-2 broker.ts legacy bucket retirement behavioral guard
// ---------------------------------------------------------------------------

test('R3-10b.3: broker.ts delegates directly to target-load-policy and enforces unified apex/IP aggregate buckets + disposal', async () => {
  // Zero legacy wrapper indirection: exported compat aliases point directly to target-load-policy resolvers.
  assert.strictEqual(externalApexBucketKey, resolveExternalApexBucketKey)
  assert.strictEqual(brokerExternalApexRpsCap, resolveExternalApexRpsCap)
  assert.strictEqual(brokerPerOriginConcurrencyCap, resolveBrokerPerOriginConcurrencyCap)
  assert.strictEqual(brokerPerOriginRpsCap, resolveBrokerPerOriginRpsCap)

  let fakeNow = 1_700_000_000_000
  const origins = ['https://a.site-one.test', 'https://b.site-one.test', 'https://c.site-two.test']
  const allowed = new Set(origins)
  const grant: Grant = {
    origin: origins[0],
    tier: 1,
    allowLocalLab: false,
    maxRpsPerOrigin: 20,
    canRead: o => allowed.has(o),
    audit: () => undefined,
  }

  const broker = new RequestBroker({
    resolve: async () => [{ address: '93.184.216.34', family: 4 }],
    transport: async () => ({ status: 200, headers: { 'content-type': 'text/plain' }, body: 'ok' }),
    now: () => fakeNow,
    externalApexMaxRps: 20,
    externalIpMaxRps: 20,
    externalIpMaxInFlight: 4,
  })

  // Send across 2 subdomains of site-one.test + 1 domain of site-two.test on the same IP.
  for (const [idx, origin] of origins.entries()) {
    const res = await broker.executeHttp(
      { origin, method: 'GET', pathAndQuery: `/u/${idx}`, runId: 'run-one' },
      grant,
      AbortSignal.timeout(5_000),
    )
    assert.equal(res.status, 200)
  }
  assert.equal(broker.getApexBucketCount(), 2, 'site-one.test and site-two.test create 2 apex buckets')
  assert.equal(broker.getIpBucketCount(), 1, 'all 3 origins share 1 per-IP aggregate bucket')
  assert.equal(broker.getIpInFlight('93.184.216.34'), 0, 'in-flight count returns to 0 after completion')

  // Second run shares site-one.test + IP bucket; disposing run-one must keep shared buckets alive and drop site-two.test.
  await broker.executeHttp(
    { origin: origins[0], method: 'GET', pathAndQuery: '/run-two', runId: 'run-two' },
    grant,
    AbortSignal.timeout(5_000),
  )
  broker.disposeRun('run-one')
  assert.equal(broker.getApexBucketCount(), 1, 'site-two.test apex bucket retired while site-one.test stays referenced')
  assert.equal(broker.getIpBucketCount(), 1, 'shared IP bucket persists while run-two references it')

  broker.disposeRun('run-two')
  assert.equal(broker.getApexBucketCount(), 0, 'all apex buckets cleaned after final run disposes')
  assert.equal(broker.getIpBucketCount(), 0, 'all IP buckets cleaned after final run disposes')

  // resetCircuit() without origin also clears unified aggregate buckets cleanly.
  fakeNow += 5_000
  await broker.executeHttp(
    { origin: origins[0], method: 'GET', pathAndQuery: '/reset-check', runId: 'run-three' },
    grant,
    AbortSignal.timeout(5_000),
  )
  assert.equal(broker.getApexBucketCount(), 1)
  assert.equal(broker.getIpBucketCount(), 1)
  broker.resetCircuit()
  assert.equal(broker.getApexBucketCount(), 0)
  assert.equal(broker.getIpBucketCount(), 0)
})
