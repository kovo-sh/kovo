/**
 * R3-09 Gate Registry Guard (`tests/gate-registry.test.ts`).
 *
 * Ensures EVERY `scripts/check-*.ts` static ratchet script on disk is actively wired into
 * either `scripts/worker-gate.sh` or `.github/workflows/verify.yml` — or explicitly listed
 * on a non-expired ticketed allowlist. Prevents check scripts from landing unwired and going
 * silently red without blocking merges.
 */
import assert from 'node:assert/strict'
import { existsSync, readdirSync, readFileSync } from 'node:fs'
import { join, resolve } from 'node:path'
import { describe, test } from 'node:test'
import { fileURLToPath } from 'node:url'

const REPO_ROOT = resolve(fileURLToPath(new URL('..', import.meta.url)))
const SCRIPTS_DIR = join(REPO_ROOT, 'scripts')
const WORKER_GATE_PATH = join(REPO_ROOT, 'scripts/worker-gate.sh')
const VERIFY_YML_PATH = join(REPO_ROOT, '.github/workflows/verify.yml')
const MERGE_STREAM_PATH = join(REPO_ROOT, 'scripts/merge-stream.sh')

interface GateAllowlistEntry {
  script: string
  owner: string
  ticket: string
  expires: string
  reason: string
}

/**
 * Ticketed allowlist for any `scripts/check-*.ts` temporarily not wired into
 * `worker-gate.sh` or `verify.yml`. Must remain empty unless a valid, non-expired
 * ticket tracks wiring.
 */
const TICKETED_UNGATED_ALLOWLIST: readonly GateAllowlistEntry[] = []

const ISO_DATE_RE = /^\d{4}-\d{2}-\d{2}$/

function listCheckScripts(scriptsDir: string): string[] {
  return readdirSync(scriptsDir)
    .filter(name => /^check-.*\.ts$/i.test(name) && !name.endsWith('.d.ts'))
    .map(name => `scripts/${name}`)
    .sort()
}

function extractReferencedCheckScripts(content: string): Set<string> {
  const found = new Set<string>()
  const re = /\bscripts\/check-[A-Za-z0-9._-]+\.ts\b/g
  for (const m of content.matchAll(re)) {
    found.add(m[0])
  }
  return found
}

function isValidIsoDate(s: string): boolean {
  if (!ISO_DATE_RE.test(s)) return false
  const ms = Date.parse(`${s}T00:00:00Z`)
  return Number.isFinite(ms) && new Date(ms).toISOString().slice(0, 10) === s
}

describe('R3-09 Gate Registry: every scripts/check-*.ts is wired into worker-gate.sh, verify.yml, or merge-stream.sh', () => {
  test('every scripts/check-*.ts on disk is referenced by worker-gate.sh, verify.yml, or merge-stream.sh (or valid non-expired ticketed allowlist)', () => {
    assert.ok(existsSync(WORKER_GATE_PATH), 'scripts/worker-gate.sh must exist')
    assert.ok(existsSync(VERIFY_YML_PATH), '.github/workflows/verify.yml must exist')
    assert.ok(existsSync(MERGE_STREAM_PATH), 'scripts/merge-stream.sh must exist')

    const onDisk = listCheckScripts(SCRIPTS_DIR)
    assert.ok(onDisk.length >= 8, `expected >= 8 check scripts on disk, found ${onDisk.length}`)

    const workerGateRefs = extractReferencedCheckScripts(readFileSync(WORKER_GATE_PATH, 'utf8'))
    const verifyYmlRefs = extractReferencedCheckScripts(readFileSync(VERIFY_YML_PATH, 'utf8'))
    const mergeStreamRefs = extractReferencedCheckScripts(readFileSync(MERGE_STREAM_PATH, 'utf8'))
    const gated = new Set<string>([...workerGateRefs, ...verifyYmlRefs, ...mergeStreamRefs])

    const today = new Date().toISOString().slice(0, 10)
    const allowlistByScript = new Map<string, GateAllowlistEntry>()
    for (const entry of TICKETED_UNGATED_ALLOWLIST) {
      assert.ok(entry.script.startsWith('scripts/check-'), `invalid allowlist script: ${entry.script}`)
      assert.ok(entry.owner.trim().length > 0, `allowlist entry ${entry.script} requires owner`)
      assert.ok(entry.ticket.trim().length > 0, `allowlist entry ${entry.script} requires ticket`)
      assert.ok(entry.reason.trim().length > 0, `allowlist entry ${entry.script} requires reason`)
      assert.ok(isValidIsoDate(entry.expires), `allowlist entry ${entry.script} has invalid ISO date: ${entry.expires}`)
      assert.ok(entry.expires >= today, `allowlist entry ${entry.script} expired on ${entry.expires}`)
      assert.ok(!gated.has(entry.script), `stale allowlist entry ${entry.script} is already gated — remove it`)
      allowlistByScript.set(entry.script, entry)
    }

    const ungated = onDisk.filter(script => !gated.has(script) && !allowlistByScript.has(script))
    assert.deepEqual(
      ungated,
      [],
      `Found ungated scripts/check-*.ts not invoked by worker-gate.sh or verify.yml: ${ungated.join(', ')}`,
    )

    // Verify all R3-09 & Wave 1b newly wired ratchets are specifically present in their gate runners
    assert.ok(workerGateRefs.has('scripts/check-direct-db-writes.ts'), 'worker-gate.sh must invoke check-direct-db-writes.ts')
    assert.ok(workerGateRefs.has('scripts/check-run-scoped-state.ts'), 'worker-gate.sh must invoke check-run-scoped-state.ts')
    assert.ok(workerGateRefs.has('scripts/check-function-growth.ts'), 'worker-gate.sh must invoke check-function-growth.ts')
    assert.ok(workerGateRefs.has('scripts/check-clones.ts'), 'worker-gate.sh must invoke check-clones.ts')
    assert.ok(workerGateRefs.has('scripts/check-verdict-flip.ts'), 'worker-gate.sh must invoke check-verdict-flip.ts')
    assert.ok(workerGateRefs.has('scripts/check-fix-provenance.ts'), 'worker-gate.sh must invoke check-fix-provenance.ts')
    assert.ok(workerGateRefs.has('scripts/check-security-optional.ts'), 'worker-gate.sh must invoke check-security-optional.ts')
    assert.ok(workerGateRefs.has('scripts/check-unwired.ts'), 'worker-gate.sh must invoke check-unwired.ts')
    assert.ok(mergeStreamRefs.has('scripts/check-kernel-review.ts'), 'merge-stream.sh must invoke check-kernel-review.ts')
    assert.ok(verifyYmlRefs.has('scripts/check-tsc-budget.ts'), 'verify.yml must invoke check-tsc-budget.ts')
  })

  test('allowlist currently holds 0 ungated scripts (full coverage)', () => {
    assert.equal(TICKETED_UNGATED_ALLOWLIST.length, 0)
  })
})
