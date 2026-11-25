// Suite self-tests: every fixture starts, exercises its intended behaviour, and stops
// without leaking state. Grading and the environment gate are covered too.
import { test } from 'node:test'
import assert from 'node:assert/strict'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { runSelfTest as enterpriseSelfTest } from '../fixtures/enterprise-spa/selftest.ts'
import { runSelfTest as wanSelfTest } from '../fixtures/wan-oob/selftest.ts'
import { runSelfTest as stagingSelfTest } from '../fixtures/staging-concurrency/selftest.ts'
import { runSelfTest as monorepoSelfTest } from '../fixtures/monorepo-whitebox/selftest.ts'
import { start as startEnterpriseSpa } from '../fixtures/enterprise-spa/index.ts'
import { FIXTURES, briefingFor, gradeFixture, gradeFixtureFile, listFixtures, startFixture } from '../run.ts'
import { loadTruth } from '../lib/grade.ts'
import type { SubmittedFinding, Truth } from '../lib/types.ts'

test('enterprise-spa fixture proves split-origin SPA + OIDC + stored XSS', { timeout: 30_000 }, async () => {
  const checks = await enterpriseSelfTest()
  assert.ok(checks.length >= 8, `expected at least 8 checks, got ${checks.length}`)
})

test('wan-oob fixture proves jitter, nonce rotation and async callbacks', { timeout: 30_000 }, async () => {
  const checks = await wanSelfTest()
  assert.ok(checks.length >= 6, `expected at least 6 checks, got ${checks.length}`)
})

test('staging-concurrency fixture proves write-BOLA, h2 race and orphan cleanup', { timeout: 30_000 }, async () => {
  const checks = await stagingSelfTest()
  assert.ok(checks.length >= 5, `expected at least 5 checks, got ${checks.length}`)
})

test('monorepo-whitebox fixture proves git history, hops and 2,500+ routes', { timeout: 30_000 }, async () => {
  const checks = await monorepoSelfTest()
  assert.ok(checks.length >= 4, `expected at least 4 checks, got ${checks.length}`)
})

test('all four fixtures start, brief and stop cleanly', { timeout: 60_000 }, async () => {
  const names = listFixtures().map((entry) => entry.name)
  assert.deepEqual(names.sort(), Object.keys(FIXTURES).sort())
  for (const name of names) {
    const fixture = await startFixture(name)
    const briefing = briefingFor(fixture)
    assert.equal(briefing.fixture, name)
    assert.ok(Object.keys(briefing.origins).length >= 1)
    assert.ok(briefing.personas.length >= 1)
    assert.ok(briefing.api.length >= 1)
    for (const origin of Object.values(briefing.origins)) {
      assert.match(origin, /^http:\/\/127\.0\.0\.1:\d+$/)
    }
    await fixture.stop()
    await fixture.stop()
  }
})

function truthFindings(truth: Truth): SubmittedFinding[] {
  return truth.findings.map((finding) => ({
    title: finding.title,
    vulnClass: finding.vulnClass,
    cwe: finding.cwe,
    origin: finding.origin,
    method: finding.method,
    endpoint: finding.endpoint,
    status: 'confirmed',
  }))
}

test('grading accepts every truth finding with full precision and recall', () => {
  for (const name of Object.keys(FIXTURES)) {
    const truth = loadTruth(name)
    const result = gradeFixture(name, truthFindings(truth))
    assert.equal(result.truePositives, truth.findings.length, `${name} tp`)
    assert.equal(result.falsePositives, 0, `${name} fp`)
    assert.equal(result.precision, 1)
    assert.equal(result.recall, 1)
    assert.equal(result.missed.length, 0)
    for (const chain of result.chains) assert.equal(chain.complete, true, `${name} chain ${chain.id}`)
  }
})

test('grading charges decoy claims and unmatched findings as false positives', () => {
  const name = 'staging-concurrency'
  const truth = loadTruth(name)
  const decoyClaims: SubmittedFinding[] = truth.decoys.map((decoy) => ({
    vulnClass: decoy.vulnClass,
    origin: decoy.origin,
    method: decoy.method,
    endpoint: decoy.endpoint,
    status: 'confirmed',
  }))
  const decoyOnly = gradeFixture(name, decoyClaims)
  assert.equal(decoyOnly.truePositives, 0)
  assert.equal(decoyOnly.falsePositives, truth.decoys.length)
  assert.equal(decoyOnly.precision, 0)

  const mixed = gradeFixture(name, [
    ...truthFindings(truth).slice(0, 1),
    ...decoyClaims.slice(0, 1),
    { vulnClass: 'sqli', method: 'GET', endpoint: '/totally/unknown', status: 'confirmed' },
  ])
  assert.equal(mixed.truePositives, 1)
  assert.equal(mixed.falsePositives, 2)
  assert.equal(mixed.precision, 1 / 3)
})

test('grading matches concrete ids against parameterized truth endpoints', () => {
  const truth = loadTruth('monorepo-whitebox')
  const result = gradeFixture('monorepo-whitebox', [
    { vulnClass: 'cross_tenant_read', method: 'GET', endpoint: '/v2/billing/invoices/inv-beta-1', status: 'confirmed' },
    { vulnClass: 'bfla', method: 'PATCH', endpoint: '/v3/admin/users/mono-bob', status: 'confirmed' },
  ])
  assert.equal(result.truePositives, 2)
  assert.equal(result.falsePositives, 0)
  assert.ok(result.chains.some((chain) => chain.id === 'mono-tenant-takeover' && chain.complete))
  assert.ok(truth.findings.length >= 4)
})

test('findings files can be arrays or { findings: [...] }', () => {
  const dir = mkdtempSync(join(tmpdir(), 'realism-grade-'))
  try {
    const claim = { vulnClass: 'bfla', method: 'GET', endpoint: '/api/admin/export', status: 'confirmed' }
    const arrayPath = join(dir, 'array.json')
    const wrappedPath = join(dir, 'wrapped.json')
    writeFileSync(arrayPath, JSON.stringify([claim]))
    writeFileSync(wrappedPath, JSON.stringify({ findings: [claim] }))
    assert.equal(gradeFixtureFile('enterprise-spa', arrayPath).truePositives, 1)
    assert.equal(gradeFixtureFile('enterprise-spa', wrappedPath).truePositives, 1)
    assert.equal(gradeFixtureFile('enterprise-spa', arrayPath).precision, 1)
  } finally {
    rmSync(dir, { recursive: true, force: true })
  }
})

test('fixtures refuse to start without KOVO_ALLOW_LOCAL_LAB=1', async () => {
  const previous = process.env.KOVO_ALLOW_LOCAL_LAB
  delete process.env.KOVO_ALLOW_LOCAL_LAB
  try {
    await assert.rejects(() => startEnterpriseSpa(), /KOVO_ALLOW_LOCAL_LAB/)
  } finally {
    if (previous === undefined) delete process.env.KOVO_ALLOW_LOCAL_LAB
    else process.env.KOVO_ALLOW_LOCAL_LAB = previous
  }
})
