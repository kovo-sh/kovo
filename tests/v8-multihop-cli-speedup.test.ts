/**
 * v8 Multi-Hop CLI Speedup contract tests (`scripts/benchmark-multihop.ts`).
 *
 * Covers Stream D (`speedup-multihop-cli`):
 *  1. `--worker-concurrency <n>` parsing, validation, and default omission (unlocking
 *     `Execution`'s dynamic AIMD Phase-B worker concurrency controller instead of clamping
 *     single-app runs to `Math.min(4, Math.max(1, args.concurrency))`).
 *  2. `--isolate-data-dir` / `--no-isolate-data-dir` default safety for `--verifier docker`
 *     so parallel single-app Docker processes never share `KOVO_DATA_DIR` / `owner` SHA-256
 *     and never kill each other's live worker containers.
 *  3. `--snapshot-after-floor` / `--resume-snapshot` / `--snapshot-max-age-ms` /
 *     `--snapshot-refresh` / `--allow-heldout-snapshot` CLI parsing & conflict guards.
 */
import assert from 'node:assert/strict'
import { execFileSync } from 'node:child_process'
import { readFileSync } from 'node:fs'
import { resolve } from 'node:path'
import { describe, it } from 'node:test'

import {
  DEFAULT_SNAPSHOT_MAX_AGE_MS,
  parseMultihopArgs,
  resolveMultihopWorkerConcurrency,
  usage,
} from '../scripts/benchmark-multihop.ts'
import { shouldIsolateDataDir } from '../scripts/benchmark-realistic.ts'

const REPO_ROOT = resolve(import.meta.dirname, '..')

describe('Stream D: benchmark-multihop CLI dynamic AIMD & Docker isolation safety', () => {
  it('omits workerConcurrency by default (unlocking dynamic AIMD) and parses explicit --worker-concurrency 1..16', () => {
    const defaults = parseMultihopArgs(['--app', 'paygrid', '--seed', '1', '--concurrency', '1'])
    assert.equal(defaults.concurrency, 1)
    assert.equal(defaults.workerConcurrency, undefined)
    assert.equal('workerConcurrency' in defaults, false)
    assert.equal(resolveMultihopWorkerConcurrency(defaults), undefined)

    // Even when cell concurrency > 1, omitting --worker-concurrency keeps workerConcurrency undefined
    const multiCell = parseMultihopArgs(['--app', 'dev', '--concurrency', '3'])
    assert.equal(multiCell.concurrency, 3)
    assert.equal(multiCell.workerConcurrency, undefined)
    assert.equal(resolveMultihopWorkerConcurrency(multiCell), undefined)

    // Explicit overrides across full 1..16 range (both space-separated and --flag=value form)
    assert.equal(parseMultihopArgs(['--worker-concurrency', '1']).workerConcurrency, 1)
    assert.equal(parseMultihopArgs(['--worker-concurrency', '8']).workerConcurrency, 8)
    assert.equal(parseMultihopArgs(['--worker-concurrency', '12']).workerConcurrency, 12)
    assert.equal(parseMultihopArgs(['--worker-concurrency', '16']).workerConcurrency, 16)
    assert.equal(parseMultihopArgs(['--worker-concurrency=10']).workerConcurrency, 10)
    assert.equal(resolveMultihopWorkerConcurrency({ workerConcurrency: 12 }), 12)

    // Defensive clamping in programmatic helper
    assert.equal(resolveMultihopWorkerConcurrency({ workerConcurrency: 0 }), 1)
    assert.equal(resolveMultihopWorkerConcurrency({ workerConcurrency: 99 }), 16)
    assert.equal(resolveMultihopWorkerConcurrency({ workerConcurrency: Number.NaN }), undefined)

    // Invalid CLI inputs reject cleanly
    assert.throws(() => parseMultihopArgs(['--worker-concurrency']), /requires an integer between 1 and 16/)
    assert.throws(() => parseMultihopArgs(['--worker-concurrency', '0']), /between 1 and 16/)
    assert.throws(() => parseMultihopArgs(['--worker-concurrency', '-2']), /between 1 and 16/)
    assert.throws(() => parseMultihopArgs(['--worker-concurrency', '17']), /between 1 and 16/)
    assert.throws(() => parseMultihopArgs(['--worker-concurrency', '2.5']), /between 1 and 16/)
    assert.throws(() => parseMultihopArgs(['--worker-concurrency', 'auto']), /between 1 and 16/)
  })

  it('wires optional workerConcurrency into storage.createRun without the legacy Math.min(4, args.concurrency) clamp', () => {
    const src = readFileSync(resolve(REPO_ROOT, 'scripts/benchmark-multihop.ts'), 'utf8')
    assert.doesNotMatch(
      src,
      /workerConcurrency:\s*Math\.min\(4,\s*Math\.max\(1,\s*args\.concurrency\)\)/,
      'legacy single-app clamp Math.min(4, Math.max(1, args.concurrency)) must be removed',
    )
    assert.match(
      src,
      /resolveMultihopWorkerConcurrency\(args\)/,
      'runCell must resolve optional workerConcurrency via resolveMultihopWorkerConcurrency(args)',
    )
    assert.match(
      src,
      /\.\.\.\(workerConcurrency !== undefined \? \{ workerConcurrency \} : \{\}\)/,
      'runCell must omit workerConcurrency when undefined so dynamic AIMD auto-scales',
    )
    assert.match(usage, /--worker-concurrency <n>/)
  })

  it('defaults isolateDataDir=true whenever --verifier docker is used unless --no-isolate-data-dir is passed', () => {
    const env = { KOVO_DATA_DIR: '/tmp/shared-kovo-data' }

    // Default for --verifier docker: isolated automatically even for single-app concurrency=1
    const dockerDefault = parseMultihopArgs(['--app', 'paygrid', '--verifier', 'docker'], env)
    assert.equal(dockerDefault.verifier, 'docker')
    assert.equal(dockerDefault.concurrency, 1)
    assert.equal(dockerDefault.isolateDataDir, true)
    assert.equal(shouldIsolateDataDir(dockerDefault), true)

    // Explicit --isolate-data-dir with --verifier docker remains supported
    const dockerExplicit = parseMultihopArgs(['--app', 'shipforge', '--verifier', 'docker', '--isolate-data-dir'], env)
    assert.equal(dockerExplicit.isolateDataDir, true)
    assert.equal(shouldIsolateDataDir(dockerExplicit), true)

    // Explicit --no-isolate-data-dir disables default isolation on single-app docker runs
    const dockerOptOut = parseMultihopArgs(['--app', 'nexusiam', '--verifier', 'docker', '--no-isolate-data-dir'], env)
    assert.equal(dockerOptOut.verifier, 'docker')
    assert.equal(dockerOptOut.isolateDataDir, false)
    assert.equal(shouldIsolateDataDir(dockerOptOut), false)

    // Non-docker verifiers preserve existing default (isolateDataDir=false unless explicitly set)
    const autoDefault = parseMultihopArgs(['--app', 'paygrid'], env)
    assert.equal(autoDefault.verifier, 'auto')
    assert.equal(autoDefault.isolateDataDir, false)
    assert.equal(shouldIsolateDataDir(autoDefault), false)

    const localJqDefault = parseMultihopArgs(['--app', 'paygrid', '--verifier', 'local-jq', '--no-llm'], env)
    assert.equal(localJqDefault.verifier, 'local-jq')
    assert.equal(localJqDefault.isolateDataDir, false)
    assert.equal(shouldIsolateDataDir(localJqDefault), false)

    const autoExplicit = parseMultihopArgs(['--app', 'paygrid', '--isolate-data-dir'], env)
    assert.equal(autoExplicit.isolateDataDir, true)
    assert.equal(shouldIsolateDataDir(autoExplicit), true)

    // Conflicting isolation flags reject cleanly
    assert.throws(
      () => parseMultihopArgs(['--verifier', 'docker', '--isolate-data-dir', '--no-isolate-data-dir'], env),
      /use either --isolate-data-dir or --no-isolate-data-dir, not both/,
    )

    // --help documents both isolation flags and exits 0 cleanly
    const helpOut = execFileSync(process.execPath, ['scripts/benchmark-multihop.ts', '--help'], {
      cwd: REPO_ROOT,
      encoding: 'utf8',
    })
    assert.match(helpOut, /--worker-concurrency <n>/)
    assert.match(helpOut, /--isolate-data-dir/)
    assert.match(helpOut, /--no-isolate-data-dir/)
  })

  it('parses --snapshot-after-floor and --resume-snapshot flags, options, and conflict guards accurately', () => {
    const capture = parseMultihopArgs([
      '--app', 'paygrid',
      '--seed', '1',
      '--mode', 'white-box',
      '--verifier', 'docker',
      '--snapshot-after-floor', '/tmp/snap-wb-s1/paygrid',
      '--snapshot-refresh',
    ])
    assert.equal(capture.snapshotAfterFloorDir, '/tmp/snap-wb-s1/paygrid')
    assert.equal(capture.resumeSnapshotDir, undefined)
    assert.equal(capture.snapshotRefresh, true)
    assert.equal(capture.snapshotMaxAgeMs, DEFAULT_SNAPSHOT_MAX_AGE_MS)
    assert.equal(capture.allowHeldoutSnapshot, false)
    assert.equal(capture.isolateDataDir, true)
    assert.equal(capture.workerConcurrency, undefined)

    const resume = parseMultihopArgs([
      '--app', 'shipforge',
      '--seed', '1',
      '--mode', 'white-box',
      '--verifier', 'docker',
      '--resume-snapshot', 'relative/snap/shipforge',
      '--snapshot-max-age-ms', '3600000',
      '--allow-heldout-snapshot',
    ])
    assert.equal(resume.resumeSnapshotDir, resolve('relative/snap/shipforge'))
    assert.equal(resume.snapshotAfterFloorDir, undefined)
    assert.equal(resume.snapshotMaxAgeMs, 3_600_000)
    assert.equal(resume.allowHeldoutSnapshot, true)
    assert.equal(resume.snapshotRefresh, false)

    // = form also parses cleanly
    const eqSnap = parseMultihopArgs(['--resume-snapshot=/tmp/snap-eq'])
    assert.equal(eqSnap.resumeSnapshotDir, '/tmp/snap-eq')

    // Missing directory, mutual exclusion, refresh-without-capture, and --no-llm conflicts
    assert.throws(
      () => parseMultihopArgs(['--snapshot-after-floor']),
      /--snapshot-after-floor requires a directory argument/,
    )
    assert.throws(
      () => parseMultihopArgs(['--snapshot-after-floor=']),
      /--snapshot-after-floor requires a directory argument/,
    )
    assert.throws(
      () => parseMultihopArgs(['--resume-snapshot']),
      /--resume-snapshot requires a directory argument/,
    )
    assert.throws(
      () => parseMultihopArgs(['--resume-snapshot=']),
      /--resume-snapshot requires a directory argument/,
    )
    assert.throws(
      () => parseMultihopArgs(['--snapshot-after-floor', '/tmp/a', '--resume-snapshot', '/tmp/b']),
      /use either --snapshot-after-floor or --resume-snapshot, not both/,
    )
    assert.throws(
      () => parseMultihopArgs(['--snapshot-refresh']),
      /--snapshot-refresh requires --snapshot-after-floor/,
    )
    assert.throws(
      () => parseMultihopArgs(['--resume-snapshot', '/tmp/a', '--no-llm']),
      /--resume-snapshot requires the live agentic model/,
    )
    assert.throws(
      () => parseMultihopArgs(['--resume-snapshot', '/tmp/a', '--snapshot-max-age-ms', '0']),
      /--snapshot-max-age-ms must be a positive integer/,
    )
  })
})
