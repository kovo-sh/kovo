import assert from 'node:assert/strict'
import { execFile, spawn } from 'node:child_process'
import { randomUUID } from 'node:crypto'
import { once } from 'node:events'
import { mkdtempSync, rmSync, writeFileSync } from 'node:fs'
import { createServer } from 'node:http'
import type { IncomingMessage, ServerResponse } from 'node:http'
import { tmpdir } from 'node:os'
import { join } from 'node:path'
import { setTimeout as delay } from 'node:timers/promises'
import { test } from 'node:test'
import { promisify } from 'node:util'
import { RequestBroker } from '../src/server/broker.ts'
import { accessPolicySnapshot } from '../src/access-policy.ts'
import { assessmentCheckIds, preparedObservation, responseCheckIds, workerHistory } from '../src/domain.ts'
import { accessPolicyReviews } from '../src/server/access-policy-checks.ts'
import { checkCoverage, readComparisons } from '../src/server/evidence-checks.ts'
import { responseEvidence, responseReview } from '../src/server/response-checks.ts'
import { restrictAccessVerification } from '../src/server/report-evidence.ts'
import { exportReportMarkdown } from '../src/server/report-export.ts'
import { parseReviewPlan, standardChecks } from '../src/server/review-plan.ts'
import { findings } from '../src/server/schema.ts'
import { assessmentAssignments, Store } from '../src/server/store.ts'
import { LinuxWorkerBackend } from '../src/server/worker-backend.ts'
import { accessPolicy } from './scenarios.ts'

const exec = promisify(execFile)

async function fixture(handler: (request: IncomingMessage, response: ServerResponse) => void, host = '127.0.0.1') {
  const server = createServer(handler).listen(0, host)
  await once(server, 'listening')
  const address = server.address()
  if (!address || typeof address === 'string') throw new Error('Fixture has no address.')
  return {
    url: `http://${host}:${address.port}`,
    close() {
      server.closeAllConnections()
      return new Promise<void>(resolve => server.close(() => resolve()))
    },
  }
}

const northstar = 'https://northstar.example'
const allowed = { origin: northstar, canRead: (origin: string) => origin === northstar, audit: () => {} }
const publicAddress = { address: '93.184.216.34', family: 4 }

test('checks DNS destinations and redirect scope before dialing', async () => {
  const attempted: string[] = []
  const privateDestination = new RequestBroker({
    resolve: async () => [publicAddress, { address: '127.0.0.1', family: 4 }],
    transport: async url => { attempted.push(url.origin); throw new Error('Unexpected connection.') },
  })
  await assert.rejects(privateDestination.readPublicRoot(allowed, new AbortController().signal), /public addresses/)
  assert.equal(attempted.length, 0)
  const redirect = new RequestBroker({
    resolve: async () => [publicAddress],
    transport: async url => {
      attempted.push(url.origin)
      return { status: 302, headers: { location: 'https://docs.northstar.example/' } }
    },
  })
  await assert.rejects(redirect.readPublicRoot(allowed, new AbortController().signal), /outside.*scope/)
  assert.deepEqual(attempted, [northstar])
})

test('checks approved scope before reading a healthy fixture and before accepting its response', async () => {
  let respond: (() => void) | undefined
  const started = Promise.withResolvers<void>()
  let count = 0
  const target = await fixture((_request, response) => {
    count += 1
    respond = () => {
      response.writeHead(200, { 'Content-Type': 'text/html', 'Strict-Transport-Security': 'max-age=31536000' }).end('Fixture page')
    }
    if (count > 1) started.resolve()
    else respond()
  })
  try {
    let approved = true
    const grant = { ...allowed, canRead: (origin: string) => origin === northstar && approved }
    const broker = new RequestBroker({
      source: 'fixture response',
      resolve: async () => [publicAddress],
      transport: async (_url, _address, signal) => {
        const response = await fetch(target.url, { signal, redirect: 'error' })
        await response.body?.cancel()
        return { status: response.status, headers: Object.fromEntries(response.headers) }
      },
    })
    const signal = new AbortController().signal
    const first = await broker.readPublicRoot(grant, signal)
    assert.equal(first.transportMaxAge, 31_536_000)
    const pending = broker.readPublicRoot(grant, signal)
    const checked = assert.rejects(pending, /outside.*scope/)
    await started.promise
    approved = false
    respond?.()
    await checked
    await assert.rejects(broker.readPublicRoot(grant, signal), /outside.*scope/)
    assert.equal(count, 2)
  } finally {
    await target.close()
  }
})

test('cancels an unresolved destination without dialing when DNS finishes', async () => {
  const lookup = Promise.withResolvers<{ address: string; family: number }[]>()
  const broker = new RequestBroker({
    resolve: () => lookup.promise,
    transport: async () => { throw new Error('Unexpected connection.') },
  })
  const controller = new AbortController()
  const read = assert.rejects(broker.readPublicRoot(allowed, controller.signal), /scope changed/)
  controller.abort(new Error('scope changed'))
  await read
  lookup.resolve([publicAddress])
})

test('links legacy candidates only to inventory that contains their origin', t => {
  const directory = mkdtempSync(join(tmpdir(), 'guardian-candidate-sources-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const storage = new Store(directory)
  const { id: projectId } = storage.createProject({ requestId: randomUUID(), name: 'Northstar', seeds: [northstar] })
  const { id: runId } = storage.createRun({ requestId: randomUUID(), projectId, goal: 'Review the supplied inventory.', sourceMode: 'prepared' })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const [original] = storage.run(runId).candidates
  const { id: laterId } = storage.addProjectAsset({
    requestId: randomUUID(), projectId, origin: 'https://docs.northstar.example',
    source: 'Later operator record', thirdParty: false,
  })
  const later = storage.projectDetail(projectId).assets.find(asset => asset.id === laterId)
  assert.ok(later)
  const { sourceEvidenceId, ...legacy } = original
  assert.ok(sourceEvidenceId)
  storage.updateRun(runId, { candidates: [legacy, later] })

  assert.deepEqual(storage.runDetail(runId).run.candidates.map(asset => asset.sourceEvidenceId), [sourceEvidenceId, undefined])
  assert.deepEqual(storage.run(runId).candidates, [legacy, later])
})

test('shows the source and original timestamp of supplied response evidence', t => {
  const directory = mkdtempSync(join(tmpdir(), 'guardian-supplied-response-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const storage = new Store(directory)
  const { id: projectId } = storage.createProject({ requestId: randomUUID(), name: 'Northstar', seeds: [northstar] })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Review the supplied response.', sourceMode: 'prepared',
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const [asset] = storage.run(runId).candidates
  storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: 0, assetIds: [asset.id], consent: true })
  storage.commitReviewPlan(storage.run(runId), standardChecks())
  const analysis = storage.workerList(runId).find(worker => worker.phase === 'analysis')
  assert.ok(analysis)
  const recordedAt = '2026-11-16T08:20:00Z'
  const supplied = preparedObservation.parse({
    status: 200, mediaType: 'text/html', transportMaxAge: 31_536_000, includeSubDomains: false, recordedAt,
  })
  assert.equal(preparedObservation.safeParse({ ...supplied, recordedAt: 'yesterday' }).success, false)
  const observation = { ...supplied, origin: northstar, finalOrigin: northstar, source: 'supplied observation' as const }
  assert.ok(!('recordedAt' in responseEvidence(observation, ['hsts'])))
  const run = storage.run(runId)
  const evidence = storage.addArtifact(run, analysis, 'observation', 'Observed public response', JSON.stringify({ observation }))
  storage.updateWorker(analysis.id, { status: 'complete', outcome: 'Recorded a supplied response.' })
  storage.writeReport(run, true)

  const detail = storage.runDetail(runId)
  assert.equal(detail.evidence.find(item => item.id === evidence.id)?.title, 'Supplied response metadata')
  assert.equal(storage.artifact(runId, evidence.id).title, 'Supplied response metadata')
  const markdown = exportReportMarkdown(storage, runId, detail.reports[0].id).content
  assert.ok(markdown.includes('Supplied response metadata · ' + northstar))
  assert.ok(markdown.includes('"recordedAt": "' + recordedAt + '"'))
  assert.equal(storage.assignmentObservation(analysis.id)?.title, 'Observed public response')
})

test('keeps reports tied to current approval and requires fresh verification after reapproval', t => {
  const directory = mkdtempSync(join(tmpdir(), 'guardian-approval-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const storage = new Store(directory)
  const docsOrigin = 'https://docs.northstar.example'
  const { id: projectId } = storage.createProject({ requestId: randomUUID(), name: 'Northstar', seeds: [northstar, docsOrigin] })
  const { id: runId } = storage.createRun({ requestId: randomUUID(), projectId, goal: 'Review <em>response metadata</em>.', sourceMode: 'public' })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const primary = storage.run(runId).candidates.find(asset => asset.origin === northstar)
  const docs = storage.run(runId).candidates.find(asset => asset.origin === docsOrigin)
  assert.ok(primary && docs)
  const approve = (assetIds: string[], expectedScopeRevision = storage.run(runId).scopeRevision) =>
    storage.command({ requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision, assetIds, consent: true })
  approve([primary.id, docs.id])
  storage.commitReviewPlan(storage.run(runId), standardChecks())

  const analysis = storage.workerList(runId).find(worker => worker.assetId === primary.id && worker.phase === 'analysis')
  const docsAnalysis = storage.workerList(runId).find(worker => worker.assetId === docs.id && worker.phase === 'analysis')
  assert.ok(analysis && docsAnalysis)
  const run = storage.updateRun(runId, { phase: 'verification' })
  const response = {
    origin: northstar, finalOrigin: northstar, status: 200, mediaType: 'text/html', transportMaxAge: null,
    includeSubDomains: false, source: 'fixture response', extraField: 'private fixture annotation',
  }
  const observation = storage.addArtifact(run, analysis, 'observation', 'Synthetic response', JSON.stringify({ observation: response }))
  const otherHost = storage.addArtifact(run, docsAnalysis, 'observation', 'Synthetic docs response',
    JSON.stringify({ observation: { ...response, origin: docsOrigin, finalOrigin: docsOrigin } }))
  storage.updateWorker(analysis.id, { status: 'complete', outcome: 'Recorded a response.' })
  storage.event(runId, 'broker.allowed', 'Recorded a fixture redirect.', { assignmentId: analysis.id, origin: docsOrigin })
  const verification = storage.makeWorker(run, 'verification', primary, 'Verify Northstar', 'Check the synthetic evidence.')
  const proof = {
    origin: northstar, checks: [{ id: 'hsts', status: 'gap' }],
    comparisons: [{ id: 'hsts', observed: null, baseline: { minimum: 1 } }],
    inputEvidence: [observation.id], interpreter: 'just-bash 3.6.1', exitStatus: 0,
    stdout: 'private fixture annotation',
  }
  const evidence = storage.addArtifact(run, verification, 'verification', 'Fixture verification', JSON.stringify(proof))
  assert.equal(storage.runDetail(runId).assignments.find(worker => worker.id === verification.id)?.inputAssignmentId, analysis.id)
  assert.throws(() => storage.makeWorker(run, 'verification', docs, 'Invalid verification', 'Review the fixture.', analysis),
    /Invalid worker input/)
  storage.updateWorker(verification.id, {
    status: 'complete', outcome: 'Confirmed from scope revision 1.',
    checks: [{ ...responseReview(null)[0].coverage, status: 'gap',
      observed: 'Header absent in the earlier capture.', reason: 'The response lacked HSTS.' }],
  })
  const findingId = randomUUID()
  storage.db.insert(findings).values({
    id: findingId, runId, assetId: primary.id, goalRevision: 0,
    finding: { id: findingId, origin: northstar, title: 'Transport policy', status: 'confirmed', severity: 'low',
      reason: 'Fixture response lacked HSTS.', remediation: 'Review the policy.', evidenceIds: [observation.id, evidence.id], scopeRevision: 1 },
  }).run()
  storage.writeReport(storage.run(runId), true)
  const original = storage.runDetail(runId).reports[0]
  assert.deepEqual(original.body.coverage.find(item => item.origin === northstar)?.checks?.map(check => check.status), ['gap'])
  assert.deepEqual(original.body.coverage.find(item => item.origin === docsOrigin)?.checks?.map(check => check.status),
    responseCheckIds.map(() => 'untested'))
  const exportOriginal = () => exportReportMarkdown(storage, runId, original.id).content
  const originalMarkdown = exportOriginal()
  assert.match(originalMarkdown, /Review &lt;em&gt;response metadata&lt;\/em&gt;/)
  assert.ok(originalMarkdown.includes(observation.id) && originalMarkdown.includes(evidence.id))
  assert.ok(!originalMarkdown.includes('private fixture annotation'))
  assert.ok(!originalMarkdown.includes(otherHost.id))

  approve([primary.id])
  assert.throws(() => approve([primary.id, docs.id], 1), /Scope changed since you opened this review/)
  assert.deepEqual(storage.run(runId).approved, [primary.id])
  assert.equal(storage.run(runId).scopeRevision, 2)
  assert.equal(workerHistory(storage.run(runId), storage.workerList(runId)).get(docsAnalysis.id), 'Host removed from scope')
  storage.writeReport(storage.run(runId), true)
  const restricted = storage.runDetail(runId).reports[0]
  assert.equal(restricted.body.findings.length, 0)
  assert.match(restricted.body.coverage[0].status, /redirect chain is no longer approved/)
  assert.deepEqual(restricted.body.coverage[0].checks?.map(({ id, status, observed }) => ({ id, status, observed })), [
    { id: 'hsts', status: 'inconclusive', observed: null },
    ...responseCheckIds.slice(1).map(id => ({ id, status: 'untested' as const, observed: null })),
  ])
  const restrictedMarkdown = exportReportMarkdown(storage, runId, restricted.id).content
  assert.doesNotMatch(restrictedMarkdown, /## Fix first/)
  assert.match(restrictedMarkdown, new RegExp(`1 check inconclusive · ${responseCheckIds.length - 1} checks untested`))
  assert.match(restrictedMarkdown, /\*\*HSTS policy\*\* · Inconclusive/)
  assert.match(restrictedMarkdown, /\*\*MIME sniffing protection\*\* · Untested/)
  for (const removed of [docsOrigin, observation.id, evidence.id, 'Header absent in the earlier capture.']) {
    assert.ok(!restrictedMarkdown.includes(removed))
  }
  assert.equal(exportOriginal(), originalMarkdown)

  approve([docs.id])
  approve([primary.id, docs.id])
  const current = assessmentAssignments(storage.workerList(runId), primary.id, 0)
  assert.equal(current.analysis?.scopeRevision, 4)
  assert.equal(current.verification, undefined)
  assert.equal(storage.runDetail(runId).assignments.find(worker => worker.id === verification.id)?.inputAssignmentId, analysis.id)
  const earlierWork = workerHistory(storage.run(runId), storage.workerList(runId))
  assert.equal(earlierWork.get(analysis.id), 'Earlier scope approval · Revision 1')
  assert.equal(earlierWork.get(verification.id), 'Earlier scope approval · Revision 1')
  assert.ok(current.analysis && !earlierWork.has(current.analysis.id))
  storage.command({ requestId: randomUUID(), runId, action: 'stop' })
  storage.command({ requestId: randomUUID(), runId, action: 'message', message: 'Which assignments are complete?' })
  assert.match(storage.runDetail(runId).messages.at(-1)?.content ?? '', /1 assignment is complete\./)
  const history = storage.runDetail(runId).reports
  const latest = history[0].body
  assert.equal(latest.findings.length, 0)
  const pending = latest.coverage.find(item => item.origin === northstar)
  assert.equal(pending?.status, 'Pending review')
  assert.equal(pending?.evidenceId, null)
  assert.deepEqual(pending?.checks?.map(check => check.status), responseCheckIds.map(() => 'untested'))
  assert.equal(history.at(-1)?.body.findings[0].id, findingId)
  assert.equal(exportOriginal(), originalMarkdown)

  const { id: otherRunId } = storage.createRun({ requestId: randomUUID(), projectId, goal: 'Independent run.', sourceMode: 'public' })
  assert.throws(() => exportReportMarkdown(storage, otherRunId, original.id), /Report version not found/)
  storage.command({ requestId: randomUUID(), runId: otherRunId, action: 'discover', consent: true })
  storage.command({ requestId: randomUUID(), runId: otherRunId, action: 'stop' })
  const pendingApproval = {
    requestId: randomUUID(), runId: otherRunId, action: 'scope' as const, expectedScopeRevision: 0,
    assetIds: [primary.id], consent: true as const,
  }
  assert.throws(() => storage.command(pendingApproval), /Scope changes are unavailable in this phase/)
  assert.equal(storage.run(otherRunId).status, 'stopped')
  storage.command({ requestId: randomUUID(), runId: otherRunId, action: 'resume' })
  storage.command(pendingApproval)
  assert.equal(storage.run(otherRunId).scopeRevision, 1)
  writeFileSync(join(directory, 'artifacts', evidence.id + '.txt'), JSON.stringify({ ...proof, inputEvidence: [otherHost.id] }))
  assert.equal(storage.runDetail(runId).assignments.find(worker => worker.id === verification.id)?.inputAssignmentId, null)
  const unavailable = exportOriginal()
  assert.match(unavailable, /Supporting record unavailable for this report version/)
  assert.ok(!unavailable.includes(otherHost.id))
  assert.ok(!unavailable.includes(evidence.id))
})

test('keeps cross-origin redirects inconclusive for the requested host', async () => {
  const finalOrigin = 'https://docs.northstar.example'
  const broker = new RequestBroker({
    resolve: async () => [publicAddress],
    transport: async url => url.origin === northstar
      ? { status: 308, headers: { location: finalOrigin + '/' } }
      : { status: 200, headers: { 'strict-transport-security': 'max-age=31536000' } },
  })
  const signal = AbortSignal.timeout(5_000)
  const observation = await broker.readPublicRoot({ ...allowed, canRead: origin => [northstar, finalOrigin].includes(origin) }, signal)
  const reviews = responseReview(observation)
  assert.equal(reviews.length, responseCheckIds.length)
  for (const review of reviews) {
    assert.equal(review.comparison, undefined)
    assert.equal(review.coverage.status, 'inconclusive')
    assert.equal(review.coverage.observed, null)
    assert.match(review.coverage.reason, /final response came from docs\.northstar\.example/)
  }
})

test('keeps older observations and ambiguous header values from confirming unsupported gaps', () => {
  const oldObservation = {
    origin: northstar, finalOrigin: northstar, status: 200, mediaType: 'text/html',
    transportMaxAge: 31_536_000, includeSubDomains: false, source: 'supplied observation' as const,
  }
  const [hsts, mime, referrer] = responseReview(oldObservation)
  assert.equal(checkCoverage(hsts, new Map([['hsts', 'met']])).status, 'met')
  assert.equal(checkCoverage(hsts, new Map([['hsts', 'gap']])).status, 'inconclusive')
  assert.equal(mime.coverage.status, 'inconclusive')
  assert.equal(referrer.coverage.status, 'inconclusive')

  const ambiguity = responseReview({ ...oldObservation, referrerPolicy: 'unrecognized' })
  assert.equal(ambiguity[2].comparison, undefined)
  const json = responseReview({ ...oldObservation, mediaType: 'application/json', referrerPolicy: 'unsafe-url' })
  assert.equal(json[2].coverage.status, 'not-applicable')
})

test('accepts only supported check identifiers as a coordinator plan', () => {
  assert.deepEqual(parseReviewPlan('{"checks":["referrer-policy","hsts","hsts"]}'), {
    source: 'coordinator', checks: ['hsts', 'referrer-policy'],
  })
  assert.equal(parseReviewPlan('{"checks":["other-check"]}'), null)
  assert.equal(parseReviewPlan('{"checks":["access-policy"]}'), null)
  assert.deepEqual(parseReviewPlan('{"checks":["access-policy"]}', assessmentCheckIds), {
    source: 'coordinator', checks: ['access-policy'],
  })
  assert.equal(parseReviewPlan('{"checks":[]}'), null)
  assert.equal(parseReviewPlan('{"checks":["hsts"],"hosts":["unapproved.example"]}'), null)
  assert.equal(parseReviewPlan('{"checks":["hsts"],"command":"unexpected operation"}'), null)
})

test('rejects a finished plan for a superseded approval before it queues assignments', t => {
  const directory = mkdtempSync(join(tmpdir(), 'guardian-plan-approval-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const storage = new Store(directory)
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Northstar', seeds: [northstar, 'https://docs.northstar.example'],
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Review the approved response records.', sourceMode: 'prepared',
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const ids = storage.run(runId).candidates.map(asset => asset.id)
  const approve = (assetIds: string[]) => storage.command({
    requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: storage.run(runId).scopeRevision, assetIds, consent: true,
  })
  approve(ids)
  const earlier = storage.run(runId)
  approve(ids.slice(1))

  storage.commitReviewPlan(earlier, standardChecks())
  assert.equal(storage.run(runId).reviewPlan?.status, 'pending')
  assert.deepEqual(storage.workerList(runId).map(worker => worker.phase), ['discovery'])

  storage.commitReviewPlan(storage.run(runId), standardChecks())
  assert.equal(storage.run(runId).reviewPlan?.status, 'ready')
  const reviews = storage.workerList(runId).filter(worker => worker.phase === 'analysis')
  assert.deepEqual(reviews.map(worker => [worker.assetId, worker.scopeRevision]), [[ids[1], 2]])
})

test('keeps completed assignments when an expanded approval selects the same checks', t => {
  const directory = mkdtempSync(join(tmpdir(), 'guardian-expanded-plan-'))
  t.after(() => rmSync(directory, { recursive: true, force: true }))
  const storage = new Store(directory)
  const docs = 'https://docs.northstar.example'
  const { id: projectId } = storage.createProject({
    requestId: randomUUID(), name: 'Northstar', seeds: [northstar, docs],
  })
  storage.importProjectAccessPolicy({
    requestId: randomUUID(), projectId, snapshot: { ...accessPolicy, origin: docs },
  })
  const { id: runId } = storage.createRun({
    requestId: randomUUID(), projectId, goal: 'Review response settings.', sourceMode: 'public',
  })
  storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
  const ids = storage.run(runId).candidates.map(asset => asset.id)
  const primary = storage.run(runId).candidates.find(asset => asset.origin === northstar)!
  const approve = (assetIds: string[], expectedScopeRevision: number) => storage.command({
    requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision, assetIds, consent: true,
  })
  approve([primary.id], 0)
  const selection = standardChecks()
  storage.commitReviewPlan(storage.run(runId), selection)
  const original = storage.workerList(runId).find(worker => worker.phase === 'analysis')!
  storage.updateWorker(original.id, { status: 'complete' })

  approve(ids, 1)
  const pending = storage.run(runId).reviewPlan
  assert.equal(pending?.status, 'pending')
  assert.deepEqual(pending?.status === 'pending' && pending.previous, selection)
  assert.deepEqual(storage.workerList(runId).filter(worker => worker.phase === 'analysis').map(worker => worker.id), [original.id])
  storage.command({ requestId: randomUUID(), runId, action: 'stop' })
  const partial = storage.runDetail(runId).reports[0]
  assert.deepEqual(partial.body.selectedChecks, selection)
  assert.ok(partial.body.gaps.includes('A revised check plan was pending for this approval.'))
  storage.command({ requestId: randomUUID(), runId, action: 'resume' })
  storage.commitReviewPlan(storage.run(runId), selection)
  const attempts = storage.workerList(runId).filter(worker => worker.phase === 'analysis')
  assert.equal(attempts.length, 2)
  assert.deepEqual(attempts.filter(worker => worker.assetId === primary.id).map(worker => [worker.id, worker.status]),
    [[original.id, 'complete']])
  assert.equal(attempts.find(worker => worker.assetId !== primary.id)?.scopeRevision, 2)
})

for (const revoked of [false, true]) {
  test(revoked ? 'rejects a saved response after an intervening redirect revocation'
    : 'keeps a reused response subject to every recorded redirect approval', t => {
    const directory = mkdtempSync(join(tmpdir(), 'guardian-reused-response-'))
    t.after(() => rmSync(directory, { recursive: true, force: true }))
    const storage = new Store(directory)
    const relay = 'https://relay.northstar.example'
    const records = 'https://records.northstar.example'
    const { id: projectId } = storage.createProject({
      requestId: randomUUID(), name: 'Northstar', seeds: [northstar, relay, records],
    })
    storage.importProjectAccessPolicy({
      requestId: randomUUID(), projectId, snapshot: { ...accessPolicy, origin: records },
    })
    const { id: runId } = storage.createRun({
      requestId: randomUUID(), projectId, goal: 'Review the approved records.', sourceMode: 'public',
    })
    storage.command({ requestId: randomUUID(), runId, action: 'discover', consent: true })
    const candidates = new Map(storage.run(runId).candidates.map(asset => [asset.origin, asset.id]))
    const approve = (...origins: string[]) => storage.command({
      requestId: randomUUID(), runId, action: 'scope', expectedScopeRevision: storage.run(runId).scopeRevision,
      assetIds: origins.map(origin => candidates.get(origin)!), consent: true,
    })
    approve(northstar, relay)
    const first = storage.run(runId)
    storage.commitReviewPlan(first, standardChecks())
    const worker = storage.workerList(runId).find(worker => worker.assetId === candidates.get(northstar))!
    for (const origin of [northstar, relay]) {
      storage.event(runId, 'broker.allowed', 'Read a fixture response.', { assignmentId: worker.id, origin })
    }
    storage.addArtifact(first, worker, 'observation', 'Observed public response', JSON.stringify({
      observation: {
        origin: northstar, finalOrigin: northstar, status: 200, mediaType: 'text/html',
        transportMaxAge: null, includeSubDomains: false, source: 'fixture response',
      },
    }), 'capture:1')
    storage.updateWorker(worker.id, { status: 'complete' })
    if (revoked) approve(northstar)
    approve(northstar, relay, records)
    const expanded = storage.run(runId)
    assert.equal(expanded.reviewPlan?.status, 'pending')
    storage.commitReviewPlan(expanded, standardChecks(assessmentCheckIds))
    const current = assessmentAssignments(storage.workerList(runId), candidates.get(northstar)!, 0).analysis!
    assert.notEqual(current.id, worker.id)
    const capture = storage.assignmentObservation(current.id)
    if (revoked) {
      assert.equal(capture, undefined)
    } else {
      assert.ok(capture)
      assert.deepEqual(storage.brokerOrigins(current).sort(), [northstar, relay].sort())
      storage.updateWorker(current.id, { status: 'complete' })
      approve(northstar, records)
      storage.command({ requestId: randomUUID(), runId, action: 'stop' })
      const report = storage.runDetail(runId).reports[0]
      const coverage = report.body.coverage.find(row => row.origin === northstar)
      assert.equal(coverage?.evidenceId, null)
      assert.match(coverage?.status ?? '', /redirect chain is no longer approved/)
      assert.ok(!exportReportMarkdown(storage, runId, report.id).content.includes(capture.id))
    }
  })
}

test('requires unique policy cases and leaves missing access decisions inconclusive', () => {
  const invalid = { ...accessPolicy, observed: [...accessPolicy.observed, accessPolicy.observed[0]] }
  assert.equal(accessPolicySnapshot.safeParse(invalid).success, false)
  assert.equal(accessPolicySnapshot.safeParse({
    ...accessPolicy, observed: [{ caseId: 'unmatched', decision: 'allow' }],
  }).success, false)
  assert.equal(accessPolicySnapshot.safeParse({
    ...accessPolicy,
    expected: [{ ...accessPolicy.expected[0], decision: 'allow', impactIfAllowed: 'organization-admin' }],
  }).success, false)
  const observedWithImpact = accessPolicySnapshot.parse({
    ...accessPolicy, observed: [{ ...accessPolicy.observed[0], impactIfAllowed: 'organization-admin' }],
  })
  assert.equal('impactIfAllowed' in observedWithImpact.observed[0], false)
  assert.equal(accessPolicyReviews(observedWithImpact)[0].rule.severity, 'medium')
  const reviews = accessPolicyReviews(accessPolicySnapshot.parse(accessPolicy))
  const comparisons = reviews.flatMap(review => review.comparison ? [review.comparison] : [])
  const unexpected = readComparisons('[{"id":"unmatched","outcome":"gap"}]', comparisons)
  assert.equal(unexpected.size, 0)
  assert.equal(checkCoverage(reviews[0], unexpected).status, 'inconclusive')
  assert.equal(checkCoverage(reviews[3], unexpected).status, 'inconclusive')
  assert.equal(reviews[3].comparison, undefined)
})

test('retains only access verdicts supported by the saved snapshot and comparison', () => {
  const source = { id: randomUUID(), content: JSON.stringify({ origin: northstar, snapshot: accessPolicy }) }
  const reviews = accessPolicyReviews(accessPolicy)
  const receipt = {
    origin: northstar, inputEvidence: [randomUUID(), source.id], exitStatus: 0,
    checks: reviews.map(({ coverage }) => ({ ...coverage, status: 'gap' })),
    comparisons: reviews.flatMap(({ comparison }) => comparison ? [{
      ...comparison, observed: comparison.id === 'access-policy:audit-summary' ? 'allow' : comparison.observed,
    }] : []),
  }
  const content = JSON.stringify(receipt)
  assert.equal(restrictAccessVerification(content, { ...source, id: randomUUID() }, northstar), undefined)
  const wrongHost = { ...source, content: JSON.stringify({
    origin: northstar, snapshot: { ...accessPolicy, origin: 'https://docs.northstar.example' },
  }) }
  assert.equal(restrictAccessVerification(content, wrongHost, northstar), undefined)
  const retained = restrictAccessVerification(content, source, northstar)
  assert.deepEqual(retained?.receipt.inputEvidence, [source.id])
  assert.deepEqual(retained?.receipt.checks.map(({ caseId, status }) => [caseId, status]), [
    ['billing-export', 'gap'], ['audit-summary', 'inconclusive'], ['read-summary', 'inconclusive'], ['modify-schedule', 'inconclusive'],
  ])
  const failed = restrictAccessVerification(JSON.stringify({ ...receipt, exitStatus: 1 }), source, northstar)
  assert.ok(failed?.receipt.checks.every(check => check.status === 'inconclusive'))
})

test('requires a local Docker Unix socket before staging worker data', async () => {
  const previous = process.env.DOCKER_HOST
  try {
    process.env.DOCKER_HOST = 'tcp://docker.example:2376'
    await assert.rejects(new LinuxWorkerBackend().run({
      assignmentId: randomUUID(), files: [], command: 'true', outputs: [],
    }, new AbortController().signal), /local Docker Unix socket/)
  } finally {
    if (previous === undefined) delete process.env.DOCKER_HOST
    else process.env.DOCKER_HOST = previous
  }
})

test('runs pipelines in the production just-bash image with read-only evidence and bounded output', async () => {
  const backend = new LinuxWorkerBackend()
  const job = {
    assignmentId: randomUUID(),
    files: [
      { name: 'observed.json', content: '{"transportMaxAge":31536000,"source":"prepared"}' },
      { name: 'baseline.txt', content: '31536000\n' },
    ],
    outputs: ['result.txt'],
  }
  const result = await backend.run({
    ...job,
    command: [
      "jq -r '.transportMaxAge' /evidence/observed.json | sort > /work/actual.txt",
      "diff /evidence/baseline.txt /work/actual.txt || exit 9",
      "cat /root/.config/guardian.key 2>/dev/null && exit 11",
      "command -v curl >/dev/null && exit 12",
      "printf 'Matched baseline.\n' > /work/result.txt",
    ].join('\n'),
  }, new AbortController().signal)
  assert.equal(result.exitCode, 0, result.stderr)
  assert.equal(result.outputs['result.txt'], 'Matched baseline.\n')
  await assert.rejects(backend.run({
    ...job, command: "printf 'changed' > /evidence/observed.json",
  }, new AbortController().signal))
})

test('enforces the worker container boundary independently of just-bash', { timeout: 19_000 }, async () => {
  const gateway = (await exec('docker', ['network', 'inspect', 'bridge', '--format', '{{(index .IPAM.Config 0).Gateway}}'])).stdout.trim()
  const target = await fixture((_request, response) => response.end('healthy'), gateway)
  const assignmentId = randomUUID()
  const abort = new AbortController()
  const pending = new LinuxWorkerBackend().run({
    assignmentId, files: [], command: 'sleep 10', outputs: [],
  }, abort.signal)
  const stopped = assert.rejects(pending)
  try {
    assert.equal(await fetch(target.url, { signal: AbortSignal.timeout(3_000) }).then(res => res.text()), 'healthy')
    const filter = 'label=dev.guardian.assignment=' + assignmentId
    let container = ''
    for (let attempt = 0; attempt < 70 && !container; attempt += 1) {
      container = (await exec('docker', ['ps', '-q', '--filter', filter])).stdout.trim()
      if (!container) await delay(50)
    }
    assert.ok(container, 'The real worker container must be running during this check.')
    const config = JSON.parse((await exec('docker', ['inspect', '--format', '{{json .HostConfig}}', container])).stdout)
    assert.equal(config.NetworkMode, 'none')
    assert.equal(config.Privileged, false)
    assert.ok(config.ReadonlyRootfs)
    assert.ok(config.Memory >= 1 && config.Memory <= 256 * 1024 * 1024)
    assert.ok(config.NanoCpus >= 1 && config.NanoCpus <= 500_000_000)
    assert.ok(config.PidsLimit >= 1 && config.PidsLimit <= 48)
    assert.match(config.Tmpfs['/tmp'], /size=8m/)
    assert.equal(config.Binds, null)
    const probe = [
      'if (process.getuid() !== 10001) process.exit(11)',
      "if (require('node:fs').existsSync('/var/run/docker.sock')) process.exit(12)",
      "if (process.env.OPENROUTER_API_KEY || process.env.GUARDIAN_DATA_DIR) process.exit(13)",
      "fetch(process.argv[1], {signal: AbortSignal.timeout(700)}).then(() => process.exit(14), () => console.log('blocked'))",
    ].join('\n')
    const result = await exec('docker', ['exec', container, 'node', '-e', probe, target.url])
    assert.equal(result.stdout.trim(), 'blocked')
  } finally {
    abort.abort()
    await stopped
    await target.close()
  }
})

test('expires a real worker whose controller keeps stdin open', { timeout: 25_000 }, async () => {
  const name = 'guardian-' + randomUUID()
  const args = ['container', 'run', '--rm', '--interactive', '--name', name, '--network', 'none',
    '--read-only', '--pull', 'never', 'guardian-worker:local']
  const child = spawn('docker', args, { stdio: ['pipe', 'ignore', 'ignore'], signal: AbortSignal.timeout(22_000) })
  const filter = ['--filter', 'name=' + name]
  const running = async () => {
    for (let attempt = 0; attempt < 60; attempt += 1) {
      const { stdout } = await exec('docker', ['container', 'ls', '--quiet', ...filter])
      if (stdout.trim()) return true
      await delay(50)
    }
    return false
  }
  try {
    const [started, [status]] = await Promise.all([running(), once(child, 'exit')])
    assert.ok(started, 'The image must reach its running state.')
    assert.equal(status, 137)
    const { stdout } = await exec('docker', ['container', 'ls', '--all', '--quiet', ...filter])
    assert.equal(stdout.trim(), '')
  } finally {
    child.stdin.destroy()
    child.kill()
    await exec('docker', ['container', 'rm', '--force', name]).catch(() => undefined)
  }
})
