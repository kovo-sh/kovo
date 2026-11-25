/**
 * v7 M1 Realism #1 — enterprise SPA.
 *
 * Unit contracts for pooled cookie hydration + the split-origin capability lane, then one
 * loopback integration run against the real fixture. The integration test grades exactly what the
 * lane persisted through the product store: >=75% capability recall (>=4/5 planted truths) at
 * 100% precision with zero decoys.
 */
import assert from 'node:assert/strict'
import { randomUUID } from 'node:crypto'
import { mkdtempSync, rmSync } from 'node:fs'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { describe, test } from 'node:test'

import { start as startEnterpriseSpa } from '../benchmarks/realism-suite/fixtures/enterprise-spa/index.ts'
import { gradeFindings, loadTruth } from '../benchmarks/realism-suite/lib/grade.ts'
import { briefingFor } from '../benchmarks/realism-suite/run.ts'
import { planCell, runSpaCapabilityLane, translateFindings } from '../scripts/benchmark-realism.ts'
import { RequestBroker } from '../src/server/broker.ts'
import type { Grant } from '../src/server/broker.ts'
import { cookieRecordsFromHeader } from '../src/server/persona-auth.ts'
import { createProjectPersona, personaSecrets, resolveRunPersonas } from '../src/server/persona-vault.ts'
import { ScopedBrowser, personaSessionBundle } from '../src/server/scoped-browser.ts'
import { Store } from '../src/server/store.ts'

process.env.GUARDIAN_ALLOW_LOCAL_LAB = '1'

function normalizeOrigin(value: string): string {
  try { return new URL(value).origin } catch { return value.replace(/\/+$/, '') }
}

describe('v7 realism1: pooled session hydration', () => {
  test('a raw Cookie header secret becomes per-origin HttpOnly cookie records', () => {
    const records = cookieRecordsFromHeader('sid=abc123; theme=dark', 'http://127.0.0.1:4321')
    assert.equal(records.length, 2)
    assert.deepEqual(records.map(record => record.name), ['sid', 'theme'])
    assert.equal(records[0]?.domain, '127.0.0.1')
    assert.equal(records[0]?.path, '/')
    assert.equal(records[0]?.httpOnly, true)
    assert.equal(records[0]?.secure, false)
  })

  test('malformed cookie fragments are dropped, never forwarded', () => {
    const records = cookieRecordsFromHeader('sid=ok; bad; =empty; x=1\r\nSet-Cookie: y=2', 'https://app.example.test')
    assert.deepEqual(records.map(record => record.name), ['sid'])
    assert.equal(records[0]?.secure, true)
  })

  test('personaSessionBundle hydrates a cookie persona without forwarding a Cookie header', () => {
    const persona = {
      id: 'p1',
      handle: 'alice-browser',
      roleLabel: 'member (tenant-alpha)',
      originAllowlist: ['http://127.0.0.1:4321'],
      authKind: 'cookie' as const,
      headerName: null,
      secret: 'sid=s3cr3t',
      canaryMarkers: [],
    }
    const grant = { personas: new Map([['alice-browser', persona]]) } as unknown as Grant
    const bundle = personaSessionBundle(grant, 'alice-browser', 'http://127.0.0.1:4321')
    assert.ok(bundle)
    assert.deepEqual(bundle?.cookies?.map(cookie => cookie.name), ['sid'])
    assert.equal(bundle?.cookies?.[0]?.httpOnly, true)
    const headers = Object.fromEntries(Object.entries(bundle?.headers ?? {}).map(([key, value]) => [key.toLowerCase(), value]))
    assert.equal(headers.cookie, undefined, 'the pooled context owns the jar; no raw Cookie header is forwarded')
  })
})

describe('v7 realism1: enterprise-spa capability lane (loopback)', () => {
  test('confirms >=4/5 planted truths at 100% precision, including hybrid HTTP->browser stored XSS', async t => {
    const dir = mkdtempSync(join(tmpdir(), 'guardian-v7-spa-'))
    const storage = new Store(dir)
    const fixture = await startEnterpriseSpa()
    const broker = new RequestBroker({ storage })
    let browser: ScopedBrowser | undefined
    t.after(async () => {
      await browser?.close().catch(() => undefined)
      await fixture.stop()
      storage.close()
      rmSync(dir, { recursive: true, force: true })
    })

    const briefing = briefingFor(fixture)
    const plan = planCell({
      fixture: 'enterprise-spa',
      briefing: { origins: briefing.origins, api: briefing.api, personas: briefing.personas },
      mode: 'grey-box',
      browserCookie: (fixture as unknown as { browserCookie: (id: string) => string }).browserCookie,
    })

    const project = storage.createProject({
      requestId: randomUUID(),
      name: 'v7 realism1 spa',
      seeds: [...new Set(Object.values(briefing.origins).map(normalizeOrigin))],
      environment: 'local-lab',
    })
    const personaIds: string[] = []
    for (const planned of plan.personas) {
      const created = createProjectPersona(storage, {
        requestId: randomUUID(),
        projectId: project.id,
        handle: planned.handle,
        roleLabel: planned.roleLabel,
        originAllowlist: Object.values(briefing.origins).map(normalizeOrigin),
        authKind: planned.authKind,
        secret: planned.secret,
        canaryMarkers: planned.canaryMarkers,
      })
      personaIds.push(created.id)
    }
    assert.equal(personaIds.length, plan.personas.length)

    const createdRun = storage.createRun({
      requestId: randomUUID(),
      projectId: project.id,
      goal: 'Defensive verification of the authorized local realism fixture.',
      sourceMode: 'public',
      capabilityTier: 3,
      approvalPolicy: 'auto_review',
      approvedPersonaIds: personaIds,
      budgetUsd: 5,
      budgetRequests: 2000,
      maxRpsPerOrigin: 10,
      workerConcurrency: 2,
      workerMaxTurns: 30,
      multiTrialEnabled: true,
    })
    storage.setEnvironmentMode(storage.run(createdRun.id), 'ephemeral_lab')
    storage.command({ requestId: randomUUID(), runId: createdRun.id, action: 'discover', consent: true })
    const targetOrigins = new Set(
      Object.entries(plan.scopes).filter(([, role]) => role === 'target').map(([label]) => normalizeOrigin(briefing.origins[label]!)),
    )
    const assetIds = storage.run(createdRun.id).candidates
      .filter(candidate => targetOrigins.has(normalizeOrigin(candidate.origin)))
      .map(candidate => candidate.id)
    assert.ok(assetIds.length > 0, 'discovery must produce a target asset')
    storage.command({
      requestId: randomUUID(),
      runId: createdRun.id,
      action: 'scope',
      expectedScopeRevision: 0,
      assetIds,
      consent: true,
      capabilityTier: 3,
      approvedPersonaIds: personaIds,
      budgetUsd: 5,
      budgetRequests: 2000,
      maxRpsPerOrigin: 10,
    })

    const run = storage.run(createdRun.id)
    const runPersonas = resolveRunPersonas(storage, project.id, personaIds)
    const approved = new Set(Object.values(briefing.origins).map(normalizeOrigin))
    const grant: Grant = {
      tier: 3,
      allowLocalLab: true,
      canRead: origin => approved.has(normalizeOrigin(origin)),
      personas: runPersonas,
      secrets: personaSecrets(runPersonas),
      audit: () => {},
    }
    browser = new ScopedBrowser(broker, {
      storage,
      resolveSessionBundle: (persona, origin) => personaSessionBundle(grant, persona, origin),
    })

    // Pooled hydration contract: the admin browser persona reaches the authenticated view (a
    // missing/forwarded-only cookie would return 403), and the member persona is denied there.
    const adminCookie = plan.personas.find(persona => persona.authKind === 'cookie' && /^admin/.test(persona.roleLabel))
    const memberCookie = plan.personas.find(persona => persona.authKind === 'cookie' && /^member/.test(persona.roleLabel))
    assert.ok(adminCookie && memberCookie)
    const [adminVisit] = await browser.visitPages([{
      origin: briefing.origins.app!,
      pathAndQuery: '/admin?tab=inbox',
      persona: adminCookie!.handle,
      waitAfterLoadMs: 300,
      runId: run.id,
    }], grant, AbortSignal.timeout(60_000))
    assert.equal(adminVisit?.status, 200, 'pooled HttpOnly cookie hydration must authenticate the admin view')
    const [memberVisit] = await browser.visitPages([{
      origin: briefing.origins.app!,
      pathAndQuery: '/admin?tab=inbox',
      persona: memberCookie!.handle,
      waitAfterLoadMs: 300,
      runId: run.id,
    }], grant, AbortSignal.timeout(60_000))
    assert.equal(memberVisit?.status, 403, 'the member browser session must not inherit the admin cookie')

    const lane = await runSpaCapabilityLane({
      storage,
      run,
      assetId: assetIds[0]!,
      broker,
      grant,
      browser,
      origins: briefing.origins,
      scopes: plan.scopes,
      routes: fixture.routes ?? [],
      personas: plan.personas.map(persona => ({
        handle: persona.handle,
        roleLabel: persona.roleLabel,
        authKind: persona.authKind,
        secret: persona.secret,
      })),
      signal: AbortSignal.timeout(120_000),
    })
    assert.ok(lane.confirmed.length >= 4, `expected >=4 confirmed proofs, got ${lane.confirmed.join(', ') || 'none'}: ${lane.notes.join(' | ')}`)
    assert.ok(lane.confirmed.some(entry => entry.startsWith('stored_xss')), 'stored XSS must be confirmed with browser evidence')

    const detail = storage.runDetail(run.id)
    const translated = translateFindings({
      findings: detail.findings,
      replaySpecs: detail.replaySpecs.map(spec => ({ id: spec.id, findingId: spec.findingId, spec: spec.spec, createdAt: spec.createdAt })),
      exchanges: detail.exchangesSummary.map(exchange => ({ id: exchange.id, method: exchange.method, pathAndQuery: exchange.pathAndQuery })),
      origins: briefing.origins,
      secrets: [],
    })
    const grade = gradeFindings(loadTruth('enterprise-spa'), translated.findings)
    assert.equal(grade.falsePositives, 0, `no decoy/unmatched submissions: ${JSON.stringify(grade)}`)
    assert.equal(grade.precision, 1)
    assert.ok(grade.recall >= 0.75, `capability recall ${grade.recall} must be >= 0.75 (${grade.truePositives}/${grade.submitted} TP)`)

    // Browser evidence is carried in the persisted finding, not inferred by the harness.
    const xss = detail.findings.find(finding => finding.category === 'stored_xss')
    assert.ok(xss)
    assert.match(`${xss?.verification ?? ''}`, /browser/i)
    assert.match(`${xss?.verification ?? ''}`, /http/i)
  })
})
